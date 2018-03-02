#!/usr/bin/env ruby

require 'bundler/setup'
require 'parallel'

require 'csv'
require 'json'
require 'net/https'
require 'openssl'
require 'resolv'
require 'uri'

class SymantecChecker

  SYMANTEC_BLACKLIST = [
    '023c81cce8e7c64fa942d3c15048707d35d9bb5b87f4f544c5bf1bc5643af2fa',
    '0999bf900bd5c297865e21e1aade6cf6bb3a94d11ae5ea798442a4e2f813241f',
    '0bdd5abe940caaabe8b2bba88348fb6f4aa4cc84436f880bece66b48bda913d8',
    '16a9e012d32329f282b10bbf57c7c0b42ae80f6ac9542eb409bc1c2cde50d322',
    '17755a5c295f3d2d72e6f031a1f07f400c588b9e582b22f17eae31a1590d1185',
    '1906c6124dbb438578d00e066d5054c6c37f0fa6028c05545e0994eddaec8629',
    '1916f3508ec3fad795f8dc4bd316f9c6085a64de3c4153ac6d62d5ea19515d39',
    '1d75d0831b9e0885394d32c7a1bfdb3dbc1c28e2b0e8391fb135981dbc5ba936',
    '22076e5aef44bb9a416a28b7d1c44322d7059f60feffa5caf6c5be8447891303',
    '25b41b506e4930952823a6eb9f1d31def645ea38a5c6c6a96d71957e384df058',
    '26c18dc6eea6f632f676bceba1d8c2b48352f29c2d5fcda878e09dcb832dd6e5',
    '2dc9470be63ef4acf1bd828609402bb7b87bd99638a643934e88682d1be8c308',
    '2dee5171596ab8f3cd3c7635fea8e6c3006aa9e31db39d03a7480ddb2428a33e',
    '3027a298fa57314dc0e3dd1019411b8f404c43c3f934ce3bdf856512c80aa15c',
    '31512680233f5f2a1f29437f56d4988cf0afc41cc6c5da6275928e9c0beade27',
    '43b3107d7342165d406cf975cd79b36ed1645048f05d7ff6ea0096e427b7db84',
    '463dbb9b0a26ed2616397b643125fbd29b66cf3a46fdb4384b209e78237a1aff',
    '479d130bf3fc61dc2f1d508d239a13276ae7b3c9841011a02c1402c7e677bd5f',
    '4905466623ab4178be92ac5cbd6584f7a1e17f27652d5a85af89504ea239aaaa',
    '495a96ba6bad782407bd521a00bace657bb355555e4bb7f8146c71bba57e7ace',
    '4ba6031ca305b09e53bde3705145481d0332b651fe30370dd5254cc4d2cb32f3',
    '5192438ec369d7ee0ce71f5c6db75f941efbf72e58441715e99eab04c2c8acee',
    '567b8211fd20d3d283ee0cd7ce0672cb9d99bc5b487a58c9d54ec67f77d4a8f5',
    '5c4f285388f38336269a55c7c12c0b3ca73fef2a5a4df82b89141e841a6c4de4',
    '67dc4f32fa10e7d01a79a073aa0c9e0212ec2ffc3d779e0aa7f9c0f0e1c2c893',
    '6b86de96a658a56820a4f35d90db6c3efdd574ce94b909cb0d7ff17c3c189d83',
    '7006a38311e58fb193484233218210c66125a0e4a826aed539ac561dfbfbd903',
    '781f1c3a6a42e3e915222db4967702a2e577aeb017075fa3c159851fddd0535e',
    '7caa03465124590c601e567e52148e952c0cffe89000530fe0d95b6d50eaae41',
    '809f2baae35afb4f36bd6476ce75c2001077901b6af5c4dab82e188c6b95c1a1',
    '81a98fc788c35f557645a95224e50cd1dac8ffb209dc1e5688aa29205f132218',
    '860a7f19210d5ead057a78532b80951453cb2907315f3ba7aa47b69897d70f3f',
    '87af34d66fb3f2fdf36e09111e9aba2f6f44b207f3863f3d0b54b25023909aa5',
    '95735473bd67a3b95a8d5f90c5a21ace1e0d7947320674d4ab847972b91544d2',
    '967b0cd93fcef7f27ce2c245767ae9b05a776b0649f9965b6290968469686872',
    '9699225c5de52e56cdd32df2e96d1cfea5aa3ca0bb52cd8933c23b5c27443820',
    '9c6f6a123cbaa4ee34dbeceee24c97d738878cb423f3c2273903424f5d1f6dd5',
    'a6f1f9bf8a0a9ddc080fb49b1efc3d1a1c2c32dc0e136a5b00c97316f2a3dc11',
    'ab3876c3da5de0c9cf6736868ee5b88bf9ba1dff9c9d72d2fe5a8d2f78302166',
    'ab39a4b025955691a40269f353fa1d5cb94eaf6c7ea9808484bbbb62fd9f68f3',
    'ab5cdb3356397356d6e691973c25b8618b65d76a90486ea7a8a5c17767f4673a',
    'ab98495276adf1ecaff28f35c53048781e5c1718dab9c8e67a504f4f6a51328f',
    'acf65e1d62cb58a2bafd6ffab40fb88699c47397cf5cb483d42d69cad34cd48b',
    'af207c61fd9c7cf92c2afe8154282dc3f2cbf32f75cd172814c52b03b7ebc258',
    'b1124142a5a1a5a28819c735340eff8c9e2f8168fee3ba187f253bc1a392d7e2',
    'b2def5362ad3facd04bd29047a43844f767034ea4892f80e56bee690243e2502',
    'bcfb44aab9ad021015706b4121ea761c81c9e88967590f6f94ae744dc88b78fb',
    'c07135f6b452398264a4776dbd0a6a307c60a36f967bd26321dcb817b5c0c481',
    'cab482cd3e820c5ce72aa3b6fdbe988bb8a4f0407ecafd8c926e36824eab92dd',
    'd2f91a04e3a61d4ead7848c8d43b5e1152d885727489bc65738b67c0a22785a7',
    'd3a25da80db7bab129a066ab41503dddffa02c768c0589f99fd71193e69916b6',
    'd4af6c0a482310bd7c54bb7ab121916f86c0c07cd52fcac32d3844c26005115f',
    'da800b80b2a87d399e66fa19d72fdf49983b47d8cf322c7c79503a0c7e28feaf',
    'f15f1d323ed9ca98e9ea95b33ec5dda47ea4c329f952c16f65ad419e64520476',
    'f2e9365ea121df5eebd8de2468fdc171dc0a9e46dadc1ab41d52790ba980a7c2',
    'f53c22059817dd96f400651639d2f857e21070a59abed9079400d9f695506900',
    'f6b59c8e2789a1fd5d5b253742feadc6925cb93edc345e53166e12c52ba2a601',
    'ff5680cd73a5703da04817a075fd462506a73506c4b81a1583ef549478d26476',
  ]

  SYMANTEC_EXCEPTIONS = [
    '56e98deac006a729afa2ed79f9e419df69f451242596d2aaf284c74a855e352e',
    '7289c06dedd16b71a7dcca66578572e2e109b11d70ad04c2601b6743bc66d07b',
    '8bb593a93be1d0e8a822bb887c547890c3e706aad2dab76254f97fb36b82fc26',
    'b5cf82d47ef9823f9aa78f123186c52e8879ea84b0f822c91d83e04279b78fd5',
    'b94c198300cec5c057ad0727b70bbe91816992256439a7b32f4598119dda9c97',
    'c0554bde87a075ec13a61f275983ae023957294b454caf0a9724e3b21b7935bc',
    'e24f8e8c2185da2f5e88d4579e817c47bf6eafbc8505f0f960fd5a0df4473ad3',
    'ec722969cb64200ab6638f68ac538e40abab5b19a6485661042a1061c4612776',
    'fae46000d8f7042558541e98acf351279589f83b6d3001c18442e4403d111849',
  ]

  SYMANTEC_MANAGED = [
    '7cac9a0ff315387750ba8bafdb1c2bc29b3f0bba16362ca93a90f84da2df5f3e',
    'ac50b5fb738aed6cb781cc35fbfff7786f77109ada7c08867c04a573fd5cf9ee',
  ]

  ROOTS = Dir['trust_stores_observatory/certificates/*'].map do |file|
    OpenSSL::X509::Certificate.new(IO.read(file))
  end.group_by do |cert|
    cert.extensions.find do |extension|
      extension.to_h['oid'] == 'subjectKeyIdentifier'
    end.to_h['value']
  end

  # times from https://security.googleblog.com/2017/09/chromes-plan-to-distrust-symantec.html
  # with a 1-week fudge factor
  M66_DEADLINE = Time.utc(2018, 4, 17+7)
  M70_DEADLINE = Time.utc(2018, 10, 23+7)

  def initialize(host)
    @host = host
  end

  def run
    hosts = [@host]

    unless @host.start_with?('www.')
      candidate = "www.#{@host}"
      # Only add the host / include in stats if the www version resolves via DNS
      hosts << candidate if Resolv.getaddresses(candidate).length > 0
    end

    hosts.map { |host| check_host(host) }
  end

  def get_chain(host)
    uri = URI("https://#{host}")
    opts = {
      use_ssl: true,
      open_timeout: 2,
      read_timeout: 2,
      ssl_timeout: 2
    }

    chain = Net::HTTP.start(uri.host, uri.port, opts) do |http|
      http.instance_variable_get(:@socket).io.peer_cert_chain.map do |pem|
        OpenSSL::X509::Certificate.new(pem)
      end
    end

    authority_key_identifier = chain.last.extensions.find do |extension|
      extension.to_h['oid'] == 'authorityKeyIdentifier'
    end

    if authority_key_identifier
      key_id = authority_key_identifier.to_h['value'].match(/^keyid:(.*)$/)[1].upcase
      # There might be multiple certificates with the same subjectKeyIdentifier
      # In this case this the last entries in the array don't make a "chain", but contain candidate
      # root certificates. If any of them are on the blacklist, we will consider the domain as
      # having a bad symantec cert, even if a different path might treat it as valid. Path building
      # is hard. This should lead to little (if any) overcounting, as almost all roots in the
      # trust_stores_observatory do contain a single cert per subjectKeyIdentifier
      chain.concat(ROOTS[key_id]) if ROOTS.key?(key_id)
    end

    chain
  end

  def check_host(host)
    chain = get_chain(host)

    public_key_hashes = chain.map do |cert|
      Digest::SHA256.hexdigest(cert.public_key.to_der)
    end

    if (SYMANTEC_BLACKLIST & public_key_hashes).length > 0 &&
        (SYMANTEC_MANAGED & public_key_hashes).empty? &&
        (SYMANTEC_EXCEPTIONS & public_key_hashes).empty?
      puts "#{host} uses bad Symantec certificate"

      if (chain.first.not_before < Time.at(1464739200).utc ||   # 2016-06-01 00:00:00 UTC
          chain.first.not_before >= Time.at(1512086400).utc)    # 2017-12-01 00:00:00 UTC
        # expiring in Chrome 66
        if (chain.first.not_after >= M66_DEADLINE)
          return [host, :M66]
        else
          return [host, :M66, :expiring_first]
        end
      else
        # expiring in Chrome 70
        if (chain.first.not_after >= M70_DEADLINE)
          return [host, :M70]
        else
          return [host, :M70, :expiring_first]
        end
      end
    else
      return [host, :good]
    end
  rescue StandardError => ex
    return [host, :error]
  end
end

def main(file)
  hosts = CSV.open(file) do |csv|
    csv.map do |index, host|
      host
    end
  end
  puts "Read #{hosts.length} hosts"

  start = Time.now.to_i
  results = Parallel.map(hosts, in_processes: 32, progress: 'Scanning hosts') do |host|
    SymantecChecker.new(host).run
  end

  IO.write("#{file}_results.json", results.to_json)
  puts "Took #{Time.now.to_i - start} seconds"
end

if __FILE__ == $0
  main(ARGV[0])
end
