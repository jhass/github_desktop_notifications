require "json"
require "http/client"
require "uri"

require "gobject/notify"
require "gobject/gtk"
require "gobject/gio"

LibNotify.init("Github")

lib LibC
  fun getpass(prompt : UInt8*) : UInt8*
  fun gethostname(name : UInt8*, len : SizeT) : Int32
end

def gethostname
  String.new(255) do |buffer|
    unless LibC.gethostname(buffer, 255u64) == 0
      raise Errno.new("Could not get hostname")
    end
    len = LibC.strlen(buffer)
    {len, len}
  end
end

module GithubDesktopNotifications
  VERSION = "0.1.0"

  class Config
    XDG_CONFIG_HOME = ENV["XDG_CONFIG_HOME"]? || File.expand_path("~/.config")
    PATH = File.join(XDG_CONFIG_HOME, "github_desktop_notifications")

    JSON.mapping({
      user: String,
      token: String
    }, true)

    def initialize(@user, @token)
    end

    def self.find_or_create
      unless File.exists? PATH
        fetcher = TokenFetcher.new

        config = Config.new(fetcher.user, fetcher.token)

        File.write PATH, config.to_json

        config
      else
        from_json File.read(PATH)
      end
    end
  end

  class Client
    class IdType
      def self.from_json(pull : JSON::PullParser)
        case pull.kind
        when :string
          pull.read_string.to_i64
        when :int
          pull.read_int
        else
          raise "Expected string or int but was #{pull.kind}"
        end
      end
    end

    class Authorization
      JSON.mapping({
        id: {type: Int64, converter: IdType},
        note: {type: String, nilable: true},
        note_url: {type: String, nilable: true},
        token: String
      })

      def self.create(client, params)
        from_json client.post("authorizations", params).body
      end

      def self.list(client)
        Array(Authorization).from_json client.get("authorizations").body
      end
    end

    class User
      JSON.mapping({
        id: {type: Int64, converter: IdType},
        login: String
      })
    end

    class Repository
      JSON.mapping({
        id: {type: Int64, converter: IdType},
        name: String,
        owner: User
      })
    end

    class Event
      JSON.mapping({
        event: String
      })
    end

    class Issue
      JSON.mapping({
        id: {type: Int64, converter: IdType},
        events_url: String
      })

      def events
        uri = URI.parse events_url
        Array(Event).from_json Client.get(uri.path).body
      end

      def self.from_url(url)
        uri = URI.parse url
        from_json Client.get(uri.path.not_nil!).body
      end
    end

    class Comment
      JSON.mapping({
        id: {type: Int64, converter: IdType},
        html_url: String,
        body: String
      })

      def self.from_url(url)
        uri = URI.parse url
        from_json Client.get(uri.path.not_nil!).body
      end
    end

    class Release
      JSON.mapping({
        id: {type: Int64, converter: IdType},
        html_url: String
      })

      def self.from_url(url)
        uri = URI.parse url
        from_json Client.get(uri.path.not_nil!).body
      end
    end

    class Notification
      class Subject
        JSON.mapping({
          title: String,
          url: String,
          latest_comment_url: String,
          type: String
        })
      end

      JSON.mapping({
        id: {type: Int64, converter: IdType},
        repository: Repository,
        subject: Subject
      })

      def self.poll(opts={} of Symbol|String => String|Bool|Int32, &block : Array(Notification) ->)
        Client.poll(->(headers : Hash(String, String)) { Client.get "notifications", opts, headers: headers }) do |response|
          begin
            block.call Array(Notification).from_json(response.body)
          rescue e : JSON::ParseException
            puts "Failed to parse: #{response.body}"
            raise e
          end
        end
      end

      def html_url
        case subject.type
        when "Issue", "PullRequest", "Commit"
          Comment.from_url(subject.latest_comment_url).html_url
        when "Release"
          Release.from_url(subject.url).html_url
        else
          pp subject.type
          raise "Not yet implemented for #{subject.type}"
        end
      end

      def title
        "#{repository.owner.login}/#{repository.name} - #{subject.title}"
      end
    end

    class Error < Exception
      class Response
        JSON.mapping({
          message: String
        })
      end

      getter headers
      getter status_code

      def initialize(message, @headers, @status_code)
        super message
      end

      def self.from_response(response)
        new Response.from_json(response.body).message, response.headers, response.status_code
      end
    end

    def self.instance
      unless @@instance
        config = GithubDesktopNotifications::Config.find_or_create
        @@instance = GithubDesktopNotifications::Client.new config.token, "x-oauth-basic"
      end

      @@instance.not_nil!
    end


    def self.poll(request, &block : HTTP::Client::Response ->)
      instance.poll(request, &block)
    end

    def self.get(endpoint, params=nil, headers=nil)
      instance.get endpoint, params, headers
    end

    def self.post(endpoint, payload, headers=nil)
      instance.post endpoint, payload, headers
    end

    def initialize(@user, @password, @otp_token=nil)
      @client = client
    end

    # Stdlib bug:
    # Reusing the client for another request in an SSL session is broken,
    # apparently
    private def client
      close
      client = HTTP::Client.new("api.github.com", ssl: true)
      client.basic_auth @user, @password
      @client = client
    end

    def poll(request : Hash(String, String) -> HTTP::Client::Response, &block : HTTP::Client::Response ->)
      headers = {} of String => String
      GLib.idle_add do
        run_poll(headers, request, block)
      end
    end

    def run_poll(headers, request : Hash(String, String) -> HTTP::Client::Response, callback : HTTP::Client::Response ->)
      response = request.call(headers)

      if response.status_code == 200
        callback.call response

        if response.headers["Last-Modified"]?
          headers["If-Modified-Since"] = response.headers["Last-Modified"]
        end
      end

      timeout = {(response.headers["X-Poll-Interval"]? || 0).to_i, 30}.max
      GLib.timeout(timeout) do
        run_poll(headers, request, callback)
      end

      false
    # Ignore timeouts, no network, unexpected responses and such
    rescue e : Errno|Socket::Error|JSON::ParseException|Error
      puts "Warning: Got #{e.class}: #{e.message}"
      true
    rescue e # Workaround 'Could not raise'
      puts "#{e.class}: #{e.message}"
      puts e.backtrace.join("\n")
      Gtk.main_quit
      false
    end

    def get(endpoint, params=nil, headers=nil)
      params ||= {} of Symbol|String => String
      query_string = params.map {|key, value| "#{key}=#{URI.escape(value.to_s)}" }.join('&')

      perform("#{normalize_endpoint(endpoint)}?#{query_string}") {|path|
        client.get(path, build_headers(headers))
      }
    end

    def post(endpoint, payload, headers=nil)
      perform(normalize_endpoint(endpoint)) {|path|
        client.post(path, build_headers(headers), payload.to_json)
      }
    end

    private def normalize_endpoint(endpoint)
      endpoint.starts_with?('/') ? endpoint : "/#{endpoint}"
    end

    private def perform(path, &request : String -> HTTP::Client::Response)
      response = request.call path

      if 301 <= response.status_code <= 302
        perform response.headers["Location"], &request
      elsif 200 <= response.status_code < 400
        response
      else
        raise Error.from_response(response)
      end
    end

    private def build_headers(additional=nil)
      HTTP::Headers{
        "Accept"     => ["application/vnd.github.v3+json"],
        "User-Agent" => ["github_desktop_notifications"]
      }.tap do |headers|
        otp_token = @otp_token
        headers["X-GitHub-OTP"] = [otp_token] if otp_token
        if additional
          additional.each do |key, value|
            headers.add key, value
          end
        end
      end
    end

    def close
      client  = @client
      client.close if client
    end

    def finalize
      close
    end
  end

  class TokenFetcher
    NOTE = "Github desktop notifications (%s)"
    NOTE_URL = "http://github.com/jhass/github_desktop_notifications"
    REQUESTED_SCOPES = %w(notifications)

    getter user
    getter token

    def initialize
      @identifer = gethostname
      @user, @password = read_credentials
      @token = fetch
    end

    private def read_credentials
      user = prompt("Github user: ")
      password = password_prompt("Password: ")
      {user, password}
    end

    private def prompt(prompt)
      print prompt
      gets.not_nil!.chomp
    end

    private def password_prompt(prompt)
      password = String.new(LibC.getpass(prompt)).chomp
    end

    private def fetch
      client = Client.new @user, @password, @otp_token

      Client::Authorization.create(client, {
        note: NOTE % @identifer,
        note_url: NOTE_URL,
        scopes: REQUESTED_SCOPES,
        fingerprint: @identifer
      }).token

    rescue e : Client::Error
      if e.headers["X-GitHub-OTP"]?
        puts e.message

        @otp_token = prompt("OTP token: ")
      elsif e.status_code == 422
        @identifer = next_identifier
      elsif 400 <= e.status_code <= 499
        puts e.message

        @user, @password = read_credentials
      else
        raise e
      end

      fetch
    end

    private def next_identifier
      digit = @identifer.match /\-(\d)$/
      if digit
        digit = digit[1].to_i
        @identifer.gsub(/\-\d$/, "-#{digit+1}")
      else
        "#{@identifer}-1"
      end
    end
  end

  class Notification
    NOTIFICATIONS_URL = "https://github.com/notifications"

    getter url
    private getter! notification

    def initialize
      @url = NOTIFICATIONS_URL
      @active = false
      @used = true
      @shown = false
    end

    private def build
      this = self
      @active = false
      @used = false
      @shown = false

      @notification = Notify::Notification.build do |n|
        n.summary = "Github"
        n.urgency = :low
        n.icon_name = icon_path

        action "default", "Show" do
          this.launch_browser
          # Compiler bug
          Pointer(Void).null.value
        end

        action "show", "Show" do
          this.launch_browser
          # Compiler bug
          Pointer(Void).null.value
        end
      end

      notification.on_closed do
        this.closed
      end
    end

    def launch_browser
      Gio::AppInfo.launch_default_for_uri url, nil unless @shown
      @shown = true
    end

    private def icon_path
      path = File.expand_path("../res/icons/GitHub-Mark-Light-64px.png", File.dirname(__FILE__))
      File.exists?(path) ? path : "github_desktop_notifications"
    end

    def closed
      @used = true
      @active = false
    end

    def update(notifications)
      return if notifications.empty?

      notification_lines = notifications.map {|notification|
        # Revisit after compiler improvements regarding can't infer block type
        notification.title as String
      }

      if @active
        notification_lines = (notification_lines + notification.body.to_s.lines).uniq
      end

      if notification_lines.size > 1
        @url = NOTIFICATIONS_URL
      else
        @url = notifications.first.html_url
      end

      if @used
        build
      end

      @active = true
      notification.body = notification_lines.join("\n")
      notification.show
    end
  end
end

notification = GithubDesktopNotifications::Notification.new
GithubDesktopNotifications::Client::Notification.poll do |notifications|
  notification.update notifications
end
