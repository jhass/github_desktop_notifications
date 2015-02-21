require "json"
require "http/client"
require "cgi"

require "gobject/notify"
require "gobject/gtk"
require "gobject/gio"

LibNotify.init("Github")

lib LibC
  fun getpass(prompt : UInt8*) : UInt8*
end

module GithubDesktopNotifications

  class Config
    XDG_CONFIG_HOME = ENV["XDG_CONFIG_HOME"]? || File.expand_path("~/.config")
    PATH = File.join(XDG_CONFIG_HOME, "github_desktop_notifications")

    json_mapping({
      user: String,
      token: String
    }, true)

    def initialize
    end

    def self.find_or_create
      unless File.exists? PATH
        fetcher = TokenFetcher.new

        config = Config.new
        config.user = fetcher.user
        config.token = fetcher.token

        File.write PATH, config.to_json

        config
      else
        from_json File.read(PATH)
      end
    end
  end

  class Client
    class IdType
      def self.new pull : JSON::PullParser
        case pull.kind
        when :string
          pull.read_string.to_i
        when :int
          pull.read_int
        else
          raise "Expected string or int but was #{pull.kind}"
        end
      end
    end

    class Authorization
      json_mapping({
        token: String
      })

      def self.create client, params
        from_json client.post("authorizations", params).body
      end
    end

    class User
      json_mapping({
        id: IdType,
        login: String
      })
    end

    class Repository
      json_mapping({
        id: IdType,
        name: String,
        owner: User
      })
    end

    class Event
      json_mapping({
        event: String
      })
    end

    class Issue
      json_mapping({
        id: IdType,
        events_url: String
      })

      def events
        uri = URI.parse events_url
        Array(Event).from_json Client.get(uri.path).body
      end

      def self.from_url url
        uri = URI.parse url
        from_json Client.get(uri.path).body
      end
    end

    class Comment
      json_mapping({
        id: IdType,
        html_url: String,
        body: String
      })

      def self.from_url url
        uri = URI.parse url
        from_json Client.get(uri.path).body
      end
    end

    class Notification
      class Subject
        json_mapping({
          title: String,
          url: String,
          latest_comment_url: String,
          type: String
        })
      end

      json_mapping({
        id: IdType,
        repository: Repository,
        subject: Subject
      })

      def self.poll opts={} of Symbol|String => String|Bool|Int32, &block : Array(Notification) ->
        Client.poll(->(headers : Hash(String, String)) { Client.get "notifications", opts, headers: headers }) do |response|
          block.call Array(Notification).from_json(response.body)
        end
      end

      def html_url
        case subject.type
        when "Issue", "PullRequest"
          Comment.from_url(subject.latest_comment_url).html_url
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
        json_mapping({
          message: String
        })
      end

      getter headers
      getter status_code

      def initialize message, @headers, @status_code
        super message
      end

      def self.from_response response
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


    def self.poll request, &block : HTTP::Response ->
      instance.poll(request, &block)
    end

    def self.get endpoint, params=nil, headers=nil
      instance.get endpoint, params, headers
    end

    def self.post endpoint, payload, headers=nil
      instance.post endpoint, payload, headers
    end

    def initialize user, password, @otp_token=nil
      @client = HTTP::Client.new("api.github.com", ssl: true)
      # @client = HTTP::Client.new("mitmproxy.dev", ssl: false)
      @client.basic_auth user, password
    end

    def poll request : Hash(String, String) -> HTTP::Response, &block : HTTP::Response ->
      headers = {} of String => String
      GLib.idle_add do
        run_poll(headers, request, block)
      end
    end

    def run_poll headers, request : Hash(String, String) -> HTTP::Response, callback : HTTP::Response ->
      response = request.call(headers)

      if response.status_code == 200
        callback.call response

        if response.headers["Last-Modified"]?
          headers["If-Modified-Since"] = response.headers["Last-Modified"]
        end
      end

      GLib.timeout(response.headers["X-Poll-Interval"].to_i) do
        # another compiler bug?
        run_poll(headers, request, callback) as Bool
      end

      false
    rescue e # Workaround 'Could not raise'
      puts e.message
      Gtk.main_quit
      false
    end

    def get endpoint, params=nil, headers=nil
      params ||= {} of Symbol|String => String
      query_string = params.map {|key, value| "#{key}=#{CGI.escape(value.to_s)}" }.join('&')

      perform("/#{endpoint}?#{query_string}") {|path|
        @client.get(path, build_headers(headers))
      }
    end

    def post endpoint, payload, headers=nil
      perform("/#{endpoint}") {|path|
        @client.post(path, build_headers(headers), payload.to_json)
      }
    end

    private def perform path, &request : String -> HTTP::Response
      response = request.call path

      if 301 <= response.status_code <= 302
        perform response.headers["Location"], &request
      elsif 200 <= response.status_code < 400
        response
      else
        raise Error.from_response(response)
      end
    end

    private def build_headers additional=nil
      HTTP::Headers{
        "Accept"     => "application/vnd.github.v3+json",
        "User-Agent" => "github_desktop_notifications"
      }.tap do |headers|
        headers["X-GitHub-OTP"] = @otp_token if @otp_token
        if additional
          additional.each do |key, value|
            headers[key] = value
          end
        end
      end
    end

    def finalize
      @client.close
    end
  end

  class TokenFetcher
    getter user
    getter token

    def initialize
      @user = prompt("Github user: ")
      @password = password_prompt("Password: ")
      @token = fetch
    end

    private def prompt prompt
      print prompt
      gets.not_nil!.chomp
    end

    private def password_prompt prompt
      password = String.new(LibC.getpass(prompt)).chomp
    end

    private def fetch
      client = Client.new @user, @password, @otp_token

      @otp_token = nil

      Client::Authorization.create(client, {
        note: "Github desktop notifications",
        note_url: "http://github.com/jhass/github_desktop_notifications",
        scopes: %w(notifications)
      }).token

    rescue e : Client::Error
      if e.headers["X-GitHub-OTP"]?
        puts e.message

        @otp_token = prompt("OTP token: ")
      elsif 400 <= e.status_code <= 499
        puts e.message

        @user = prompt("Github user: ")
        @password = password_prompt("Passowrd: ")
      else
        raise e
      end

      fetch
    end
  end

  class Notification
    NOTIFICATIONS_URL = "https://github.com/notifications"
    getter! url
    private getter! notification
    property! active
    property! used

    def initialize
      @url = NOTIFICATIONS_URL
      @active = false
      @used = true
    end

    private def build
      this = self
      @active = false
      @used = false

      @notification = Notify::Notification.build do |n|
        n.summary = "Github"
        n.urgency = :low
        n.icon_name = File.expand_path("../res/icons/GitHub-Mark-Light-64px.png", File.dirname(__FILE__))

        action "show", "Show" do
          Gio::AppInfo.launch_default_for_uri this.url, nil
          # Compiler bug
          Pointer(Void).null.value
        end
      end

      notification.connect "closed" do
        this.used = true
        this.active = false
      end
    end

    def update notifications
      return if notifications.empty?

      if active || notifications.size > 1
        @url = NOTIFICATIONS_URL
      else
        @url = notifications.first.html_url
      end

      # Compiler bug: This cast missing, causes can't infer block return type in Array#map calls _elsewhere_
      # This one is "fixed" by the no-block-free-var branch
      notifications = notifications.map {|notification| notification.title as String }

      if active
        notifications = (notifications + notification.body.to_s.lines).uniq
      end

      if used
        build
      end

      @active = true
      notification.body = notifications.join("\n")
      notification.show
    end
  end
end

notification = GithubDesktopNotifications::Notification.new
GithubDesktopNotifications::Client::Notification.poll do |notifications|
  notification.update notifications
end
