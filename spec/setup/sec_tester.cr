require "lucky_sec_tester"

LuckySecTester.configure do |setting|
  setting.nexploit_token = ENV["NEXPLOIT_TOKEN"]
end
