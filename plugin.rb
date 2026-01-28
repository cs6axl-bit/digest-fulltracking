# name: digest-fulltracking
# about: POST to external endpoint after digest email is sent (failsafe, async) + optional open tracking pixel + optional link-parameter appending + debug logs
# version: 2.1
# authors: you

after_initialize do
  require "net/http"
  require "uri"
  require "cgi"
  require "time"
  require "securerandom"
  require "base64"
  require_dependency "user_notifications"

  begin
    require "nokogiri"
  rescue LoadError
    Nokogiri = nil
  end

  module ::DigestReport
    PLUGIN_NAME = "digest-fulltracking"

    # =========================
    # HARD-CODED SETTINGS (edit here)
    # =========================
    ENABLED = true
    ENDPOINT_URL = "https://ai.templetrends.com/digest_report.php"

    # Open tracking
    OPEN_TRACKING_ENABLED = true
    OPEN_TRACKING_PIXEL_BASE_URL = "https://ai.templetrends.com/digest_open.php"

    # Link appending (DO IT LIKE THE WORKING PLUGIN)
    APPEND_LINK_DATA_ENABLED = true
    SKIP_UNSUB_AND_PREF_LINKS = true

    DEBUG_LOG = true

    # POST fields
    EMAIL_ID_FIELD           = "email_id"
    OPEN_TRACKING_USED_FIELD = "open_tracking_used"

    TOPIC_IDS_FIELD      = "topic_ids"
    TOPIC_COUNT_FIELD    = "topic_ids_count"
    FIRST_TOPIC_ID_FIELD = "first_topic_id"

    SUBJECT_FIELD       = "subject"
    SUBJECT_PRESENT_FLD = "subject_present"
    FROM_EMAIL_FIELD    = "from_email"

    USER_ID_FIELD         = "user_id"
    USERNAME_FIELD        = "username"
    USER_CREATED_AT_FIELD = "user_created_at_utc"

    SUBJECT_MAX_LEN  = 300
    FROM_MAX_LEN     = 200
    USERNAME_MAX_LEN = 200

    OPEN_TIMEOUT_SECONDS  = 3
    READ_TIMEOUT_SECONDS  = 3
    WRITE_TIMEOUT_SECONDS = 3

    JOB_RETRY_COUNT = 2
    # =========================

    STORE_NAMESPACE = PLUGIN_NAME
    def self.store_key_last_email_id(user_id)
      "last_email_id_user_#{user_id}"
    end

    def self.log(msg)
      Rails.logger.info("[#{PLUGIN_NAME}] #{msg}")
    rescue StandardError
    end

    def self.log_error(msg)
      Rails.logger.error("[#{PLUGIN_NAME}] #{msg}")
    rescue StandardError
    end

    def self.dlog(msg)
      return unless DEBUG_LOG
      log("DEBUG #{msg}")
    rescue StandardError
    end

    def self.dlog_error(msg)
      return unless DEBUG_LOG
      log_error("DEBUG #{msg}")
    rescue StandardError
    end

    def self.enabled?
      return false unless ENABLED
      return false if ENDPOINT_URL.to_s.strip.empty?
      true
    rescue StandardError
      false
    end

    def self.open_tracking_enabled?
      return false unless OPEN_TRACKING_ENABLED
      return false if OPEN_TRACKING_PIXEL_BASE_URL.to_s.strip.empty?
      true
    rescue StandardError
      false
    end

    def self.append_link_data_enabled?
      return false unless APPEND_LINK_DATA_ENABLED
      true
    rescue StandardError
      false
    end

    def self.safe_str(v, max_len)
      s = v.to_s.strip
      s = s[0, max_len] if s.length > max_len
      s
    rescue StandardError
      ""
    end

    def self.safe_iso8601(t)
      return "" if t.nil?
      begin
        tt = t.respond_to?(:utc) ? t.utc : t
        tt.iso8601
      rescue StandardError
        ""
      end
    end

    def self.header_val(message, key)
      begin
        v = message&.header&.[](key)
        v.to_s.strip
      rescue StandardError
        ""
      end
    end

    def self.set_header!(message, k, v)
      message.header[k] = v.to_s
      true
    rescue StandardError
      false
    end

    # Generate a random 20-digit numeric string.
    def self.random_20_digit_id
      digits = +""
      20.times { digits << SecureRandom.random_number(10).to_s }
      digits
    rescue StandardError
      t = (Time.now.to_f * 1000).to_i.to_s
      (t + "0" * 20)[0, 20]
    end

    # Ensure the message has an email_id header (generate once)
    def self.ensure_email_id!(message)
      eid = header_val(message, "X-Digest-Report-Email-Id")
      return eid unless eid.empty?

      eid = random_20_digit_id
      set_header!(message, "X-Digest-Report-Email-Id", eid)
      eid
    rescue StandardError
      random_20_digit_id
    end

    def self.store_last_email_id_for_user(user_id, email_id)
      return if user_id.to_i <= 0
      return if email_id.to_s.strip.empty?
      PluginStore.set(STORE_NAMESPACE, store_key_last_email_id(user_id.to_i), email_id.to_s.strip)
      true
    rescue StandardError
      false
    end

    def self.encoded_email_b64url(email)
      e = email.to_s.strip
      return "" if e.empty?
      Base64.urlsafe_encode64(e, padding: false)
    rescue StandardError
      ""
    end

    # ====== The EXACT link rewrite style from the working plugin (digest-append-data) ======
    def self.rewrite_digest_links_like_working_plugin!(message, user, email_id)
      return if message.nil?
      return unless append_link_data_enabled?

      base = Discourse.base_url.to_s
      return if base.empty?

      html_part =
        if message.respond_to?(:html_part) && message.html_part
          message.html_part
        else
          message
        end

      body = html_part.body&.decoded
      return if body.nil? || body.empty?

      dayofweek_val = encoded_email_b64url(user&.email)

      # Prefer Nokogiri if available (same as your working plugin)
      if Nokogiri
        doc = Nokogiri::HTML(body)

        changed = 0

        doc.css("a[href]").each do |a|
          href = a["href"].to_s.strip
          next if href.empty?

          next if href.start_with?("mailto:", "tel:", "sms:", "#")

          is_relative = href.start_with?("/")
          is_internal = href.start_with?(base)
          next unless is_relative || is_internal

          if SKIP_UNSUB_AND_PREF_LINKS
            next if href.include?("/email/unsubscribe") || href.include?("/my/preferences")
          end

          begin
            uri = URI.parse(is_relative ? (base + href) : href)
          rescue URI::InvalidURIError
            next
          end

          next unless uri.scheme.nil? || uri.scheme == "http" || uri.scheme == "https"

          params = URI.decode_www_form(uri.query || "")

          params << ["isdigest", "1"] unless params.any? { |k, _| k == "isdigest" }
          params << ["u", user.id.to_s] unless params.any? { |k, _| k == "u" }
          params << ["dayofweek", dayofweek_val] unless dayofweek_val.empty? || params.any? { |k, _| k == "dayofweek" }

          # NEW: email_id param
          params << ["email_id", email_id.to_s] unless email_id.to_s.empty? || params.any? { |k, _| k == "email_id" }

          old = a["href"].to_s
          uri.query = URI.encode_www_form(params)
          a["href"] = uri.to_s
          changed += 1 if a["href"].to_s != old
        end

        html_part.body = doc.to_html
        dlog("append-links: nokogiri changed=#{changed} user_id=#{user.id} email_id=#{email_id}")
      else
        # Fallback regex path (same spirit as your old plugin)
        html_part.body = body.gsub(/href="(#{Regexp.escape(base)}[^"]*|\/[^"]*)"/) do
          url = Regexp.last_match(1)
          next %{href="#{url}"} if (SKIP_UNSUB_AND_PREF_LINKS && (url.include?("/email/unsubscribe") || url.include?("/my/preferences")))

          joiner = url.include?("?") ? "&" : "?"
          extra = "isdigest=1&u=#{user.id}"
          extra += "&dayofweek=#{dayofweek_val}" unless dayofweek_val.empty?
          extra += "&email_id=#{CGI.escape(email_id.to_s)}" unless email_id.to_s.empty?

          %{href="#{url}#{joiner}#{extra}"}
        end

        dlog("append-links: regex user_id=#{user.id} email_id=#{email_id}")
      end
    rescue StandardError => e
      dlog_error("append-links error err=#{e.class}: #{e.message}")
    end

    # ===== Pixel helpers =====
    def self.extract_email_body(message)
      return "" if message.nil?
      if message.respond_to?(:multipart?) && message.multipart?
        html = ""
        txt  = ""
        begin
          html = message.html_part&.body&.decoded.to_s
        rescue StandardError
          html = ""
        end
        begin
          txt = message.text_part&.body&.decoded.to_s
        rescue StandardError
          txt = ""
        end
        return html unless html.to_s.empty?
        return txt unless txt.to_s.empty?
      end
      message.body&.decoded.to_s
    rescue StandardError
      ""
    end

    def self.message_already_has_pixel?(mail_message)
      b = extract_email_body(mail_message)
      return false if b.to_s.empty?
      b.include?(OPEN_TRACKING_PIXEL_BASE_URL.to_s.strip)
    rescue StandardError
      false
    end

    def self.build_tracking_pixel_html(email_id:, user_id:, user_email:)
      base = OPEN_TRACKING_PIXEL_BASE_URL.to_s.strip
      return "" if base.empty?

      q = { "email_id" => email_id.to_s, "user_id" => user_id.to_s, "user_email" => user_email.to_s }

      url =
        begin
          uri = URI.parse(base)
          existing = uri.query.to_s
          add = URI.encode_www_form(q)
          uri.query = existing.empty? ? add : "#{existing}&#{add}"
          uri.to_s
        rescue StandardError
          "#{base}?#{URI.encode_www_form(q)}"
        end

      %Q(<img src="#{CGI.escapeHTML(url)}" width="1" height="1" style="display:none!important;max-height:0;overflow:hidden" alt="" />)
    rescue StandardError
      ""
    end

    def self.inject_pixel_into_mail!(mail_message, email_id:, user_id:, user_email:)
      return false if mail_message.nil?

      pixel = build_tracking_pixel_html(email_id: email_id, user_id: user_id, user_email: user_email)
      return false if pixel.to_s.empty?

      if mail_message.respond_to?(:multipart?) && mail_message.multipart?
        hp = mail_message.html_part rescue nil
        return false if hp.nil?
        html = (hp.body.decoded.to_s rescue "")
        return false if html.empty?
        hp.body = (html.include?("</body>") ? html.sub("</body>", "#{pixel}</body>") : (html + pixel))
        return true
      end

      ct = (mail_message.content_type.to_s rescue "")
      return false unless ct.downcase.include?("text/html")
      html = (mail_message.body.decoded.to_s rescue "")
      return false if html.empty?

      mail_message.body = (html.include?("</body>") ? html.sub("</body>", "#{pixel}</body>") : (html + pixel))
      true
    rescue StandardError => e
      dlog_error("inject_pixel error err=#{e.class}: #{e.message}")
      false
    end

    # ===== After-send topic extraction (unchanged) =====
    def self.extract_topic_ids_from_message(message)
      body = extract_email_body(message)
      return [] if body.to_s.empty?

      begin
        body = CGI.unescapeHTML(body.to_s)
      rescue StandardError
        body = body.to_s
      end

      urls = body.scan(%r{https?://[^\s"'<>()]+}i) rescue []
      ids = []
      seen = {}

      urls.each do |raw|
        next if raw.to_s.empty?
        u = raw.to_s.gsub(/[)\].,;]+$/, "")
        uri = (URI.parse(u) rescue nil)
        next if uri.nil?
        path = uri.path.to_s
        next if path.empty?
        m = path.match(%r{/t/(?:[^/]+/)?(\d+)(?:/|$)}i)
        next if m.nil?
        tid = m[1].to_i
        next if tid <= 0
        next if seen[tid]
        seen[tid] = true
        ids << tid
      end

      ids
    rescue StandardError => e
      log_error("extract_topic_ids_from_message error err=#{e.class}: #{e.message}")
      []
    end
  end

  # ==========================================================
  # 1) DO LINK APPEND THE SAME WAY AS THE WORKING PLUGIN:
  #    prepend UserNotifications#digest and rewrite links there.
  #    ALSO: generate/stamp email_id there so it matches pixel later.
  # ==========================================================
  module ::DigestReportDigestHook
    def digest(user, opts = {})
      super.tap do |message|
        begin
          next unless ::DigestReport.enabled?
          next if message.nil?

          # Ensure email_id exists early (this is the "shared id" for links + pixel)
          email_id = ::DigestReport.ensure_email_id!(message)

          if user && user.id.to_i > 0
            ::DigestReport.store_last_email_id_for_user(user.id, email_id)
          end

          if ::DigestReport.append_link_data_enabled? && user
            ::DigestReport.rewrite_digest_links_like_working_plugin!(message, user, email_id)
          end

          ::DigestReport.dlog("digest(): prepared email_id=#{email_id} user_id=#{user&.id} append_links=#{::DigestReport.append_link_data_enabled?}")
        rescue StandardError => e
          ::DigestReport.dlog_error("digest() hook error err=#{e.class}: #{e.message}")
        end
      end
    end
  end

  class ::UserNotifications
    prepend ::DigestReportDigestHook
  end

  # ==========================================================
  # 2) BEFORE send: only handle PIXEL injection + headers,
  #    reusing the SAME email_id stamped in digest().
  # ==========================================================
  DiscourseEvent.on(:before_email_send) do |message, email_type|
    begin
      next unless ::DigestReport.enabled?
      next unless email_type.to_s == "digest"

      email_id = ::DigestReport.ensure_email_id!(message)

      # prevent double pixel logic
      already_set = ::DigestReport.header_val(message, "X-Digest-Report-Open-Tracking-Used")
      if !already_set.empty?
        ::DigestReport.dlog("before_email_send: open-tracking header already set -> skip pixel (email_id=#{email_id})")
        next
      end

      recipient = Array(message&.to).first.to_s.strip rescue ""
      user = (recipient.empty? ? nil : User.find_by_email(recipient) rescue nil)
      uid = user ? user.id : 0

      injected = false
      if ::DigestReport.open_tracking_enabled?
        if ::DigestReport.message_already_has_pixel?(message)
          injected = true
          ::DigestReport.dlog("before_email_send: pixel already present -> injected=true (email_id=#{email_id})")
        else
          injected = ::DigestReport.inject_pixel_into_mail!(message, email_id: email_id, user_id: uid, user_email: recipient)
        end
      end

      open_used = injected ? "1" : "0"
      ::DigestReport.set_header!(message, "X-Digest-Report-Open-Tracking-Used", open_used)
      ::DigestReport.set_header!(message, "X-Digest-Report-User-Id", uid.to_s)

      ::DigestReport.dlog("before_email_send: email_id=#{email_id} user_id=#{uid} injected=#{injected} open_used=#{open_used}")
    rescue StandardError => e
      ::DigestReport.dlog_error("before_email_send error err=#{e.class}: #{e.message}")
    end
  end

  # ==========================================================
  # Job: postback (same as before, reads email_id from header via after hook)
  # ==========================================================
  class ::Jobs::DigestReportPostback < ::Jobs::Base
    sidekiq_options queue: "low", retry: ::DigestReport::JOB_RETRY_COUNT

    def execute(args)
      begin
        return unless ::DigestReport.enabled?

        url = ::DigestReport::ENDPOINT_URL.to_s.strip
        uri = (URI.parse(url) rescue nil)
        return ::DigestReport.log_error("Invalid ENDPOINT_URL #{url.inspect}") if uri.nil?
        return ::DigestReport.log_error("Invalid ENDPOINT_URL scheme #{url.inspect}") unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)

        email_id = args[:email_id].to_s.strip
        email_id = ::DigestReport.random_20_digit_id if email_id.empty?

        open_tracking_used = args[:open_tracking_used].to_s.strip
        open_tracking_used = "0" unless open_tracking_used == "1"

        user_email = args[:user_email].to_s.strip
        subject = ::DigestReport.safe_str(args[:subject], ::DigestReport::SUBJECT_MAX_LEN)
        subject_present = subject.empty? ? "0" : "1"
        from_email = ::DigestReport.safe_str(args[:from_email], ::DigestReport::FROM_MAX_LEN)

        user_id  = args[:user_id].to_s
        username = ::DigestReport.safe_str(args[:username], ::DigestReport::USERNAME_MAX_LEN)
        user_created_at_utc = args[:user_created_at_utc].to_s

        incoming_ids = Array(args[:topic_ids]).map { |x| x.to_i }
        seen = {}
        topic_ids_ordered = []
        incoming_ids.each do |tid|
          next if tid <= 0
          next if seen[tid]
          seen[tid] = true
          topic_ids_ordered << tid
        end

        topic_ids_csv   = topic_ids_ordered.join(",")
        topic_ids_count = topic_ids_ordered.length
        first_topic_id  = topic_ids_ordered[0] ? topic_ids_ordered[0].to_s : ""

        form_kv = [
          [::DigestReport::EMAIL_ID_FIELD, email_id],
          [::DigestReport::OPEN_TRACKING_USED_FIELD, open_tracking_used],
          ["user_email", user_email],

          [::DigestReport::FROM_EMAIL_FIELD, from_email],

          [::DigestReport::USER_ID_FIELD, user_id],
          [::DigestReport::USERNAME_FIELD, username],
          [::DigestReport::USER_CREATED_AT_FIELD, user_created_at_utc],

          [::DigestReport::SUBJECT_FIELD, subject],
          [::DigestReport::SUBJECT_PRESENT_FLD, subject_present],

          [::DigestReport::TOPIC_IDS_FIELD, topic_ids_csv],
          [::DigestReport::TOPIC_COUNT_FIELD, topic_ids_count.to_s],
          [::DigestReport::FIRST_TOPIC_ID_FIELD, first_topic_id]
        ]

        body = URI.encode_www_form(form_kv)

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == "https")
        http.open_timeout = ::DigestReport::OPEN_TIMEOUT_SECONDS
        http.read_timeout = ::DigestReport::READ_TIMEOUT_SECONDS
        http.write_timeout = ::DigestReport::WRITE_TIMEOUT_SECONDS if http.respond_to?(:write_timeout=)

        req = Net::HTTP::Post.new(uri.request_uri)
        req["Content-Type"] = "application/x-www-form-urlencoded"
        req["User-Agent"] = "Discourse/#{Discourse::VERSION::STRING} #{::DigestReport::PLUGIN_NAME}"
        req.body = body

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

        begin
          res = http.start { |h| h.request(req) }
          ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
          code = res.code.to_i

          if code >= 200 && code < 300
            ::DigestReport.log("POST OK code=#{res.code} ms=#{ms} email_id=#{email_id} open_tracking_used=#{open_tracking_used} topic_ids_count=#{topic_ids_count} first_topic_id=#{first_topic_id}")
          else
            ::DigestReport.log_error("POST FAIL code=#{res.code} ms=#{ms} email_id=#{email_id} open_tracking_used=#{open_tracking_used} topic_ids_count=#{topic_ids_count} body=#{res.body.to_s[0, 500].inspect}")
          end
        rescue StandardError => e
          ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
          ::DigestReport.log_error("POST ERROR ms=#{ms} email_id=#{email_id} open_tracking_used=#{open_tracking_used} topic_ids_count=#{topic_ids_count} err=#{e.class}: #{e.message}")
        ensure
          begin
            http.finish if http.started?
          rescue StandardError
          end
        end
      rescue StandardError => e
        ::DigestReport.log_error("JOB CRASH err=#{e.class}: #{e.message}")
      end
    end
  end

  # ==========================================================
  # After send: enqueue postback
  # ==========================================================
  DiscourseEvent.on(:after_email_send) do |message, email_type|
    begin
      next unless ::DigestReport.enabled?
      next unless email_type.to_s == "digest"

      recipient = Array(message&.to).first.to_s.strip rescue ""

      subject = ::DigestReport.safe_str(message&.subject, ::DigestReport::SUBJECT_MAX_LEN) rescue ""
      from_email = (Array(message&.from).first.to_s.strip rescue "")

      user = (recipient.empty? ? nil : User.find_by_email(recipient) rescue nil)
      user_id = user ? user.id : ""
      username = user ? user.username.to_s : ""
      user_created_at_utc = user ? ::DigestReport.safe_iso8601(user.created_at) : ""

      topic_ids = ::DigestReport.extract_topic_ids_from_message(message)

      email_id = ::DigestReport.header_val(message, "X-Digest-Report-Email-Id")
      email_id = ::DigestReport.random_20_digit_id if email_id.to_s.strip.empty?

      open_tracking_used = ::DigestReport.header_val(message, "X-Digest-Report-Open-Tracking-Used")
      open_tracking_used = (open_tracking_used == "1" ? "1" : "0")

      Jobs.enqueue(
        :digest_report_postback,
        email_id: email_id,
        open_tracking_used: open_tracking_used,
        user_email: recipient,
        from_email: from_email,
        user_id: user_id,
        username: username,
        user_created_at_utc: user_created_at_utc,
        subject: subject,
        topic_ids: topic_ids
      )

      first_topic_id = topic_ids[0] ? topic_ids[0].to_s : ""
      ::DigestReport.log("Enqueued postback email_id=#{email_id} open_tracking_used=#{open_tracking_used} user_found=#{!user.nil?} topic_ids_count=#{topic_ids.length} first_topic_id=#{first_topic_id}")
    rescue StandardError => e
      ::DigestReport.log_error("ENQUEUE ERROR err=#{e.class}: #{e.message}")
    end
  end
end
