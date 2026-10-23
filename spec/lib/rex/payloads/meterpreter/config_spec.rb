require 'spec_helper'

RSpec.describe Rex::Payloads::Meterpreter::Config do
  subject(:config) do
    described_class.new(
      ascii_str: true,
      uuid: Msf::Payload::UUID.new(raw: 'U' * 16),
      session_guid: session_guid,
      expiration: 123,
      transports: transports,
      extensions: [],
      ext_format: 'bin'
    )
  end

  let(:session_guid) { 'G' * 16 }
  let(:transports) { [] }

  def parse_config(raw)
    packet = Rex::Post::Meterpreter::Packet.new
    packet.raw = raw
    packet.from_r
    packet
  end

  it 'uses an explicitly supplied session GUID' do
    packet = parse_config(config.to_b)

    expect(packet.get_tlv_value(Rex::Post::Meterpreter::TLV_TYPE_SESSION_GUID)).to eq(session_guid)
  end

  context 'with a serialized C2 group' do
    let(:transports) { [{ c2_tlv: c2_tlv }] }
    let(:c2_tlv) do
      get = Rex::Post::Meterpreter::GroupTlv.new(Rex::Post::Meterpreter::TLV_TYPE_C2_GET)
      get.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_C2_URI, '/profiled-get')
      get.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_C2_ENC_INBOUND, Rex::Post::Meterpreter::C2_ENCODING_B64)

      c2 = Rex::Post::Meterpreter::GroupTlv.new(Rex::Post::Meterpreter::TLV_TYPE_C2)
      c2.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_C2_URL, 'https://192.0.2.1:8443/bootstrap')
      c2.tlvs << get
      c2
    end

    it 'preserves the complete group without reconstructing it' do
      packet = parse_config(config.to_b)

      expect(packet.get_tlv(Rex::Post::Meterpreter::TLV_TYPE_C2).to_r).to eq(c2_tlv.to_r)
    end
  end
end
