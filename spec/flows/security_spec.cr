{% skip_file unless flag?(:with_sec_tests) %}

require "../spec_helper"

describe "SecTester" do
  # Testing the auth page with SQLi attack
  it "Testing sign_in page for SQLi, OSI, XSS attacks" do
    with_cleanup(scanner) do
      target = scanner.build_target(SignIns::Create) do |t|
        t.body = "user%3Aemail=test%40test.com&user%3Apassword=1234"
      end
      scanner.run_check(
        scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
        tests: [
          "sqli",
          "osi",
          "xss",
        ],
        target: target
      )
    end
  end

  it "Testing sign_up page for ALL attacks" do
    with_cleanup(scanner) do
      target = scanner.build_target(SignUps::Create) do |t|
        t.body = "user%3Aemail=aa%40aa.com&user%3Apassword=123456789&user%3Apassword_confirmation=123456789"
      end
      scanner.run_check(
        scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
        tests: nil,
        target: target
      )
    end
  end

  # Testing the auth page with Dom XSS attack
  it "Testing sign_in for dom based XSS" do
    with_cleanup(scanner) do
      target = scanner.build_target(SignIns::New)
      scanner.run_check(
        scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
        tests: "dom_xss",
        target: target
      )
    end
  end

  # Testing the auth page with Headers Security attack
  it "testing root for header security issues" do
    with_cleanup(scanner) do
      target = scanner.build_target
      scanner.run_check(
        scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
        tests: "header_security",
        target: target
      )
    end
  end

  # Testing the auth page with Cookies Security attack
  it "testing root for cookie security issues" do
    with_cleanup(scanner) do
      target = scanner.build_target
      scanner.run_check(
        scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
        tests: "cookie_security",
        target: target
      )
    end
  end

  # Testing JS file for 3rd party issues
  it "Tests /js/app.js for 3rd party issues" do
    with_cleanup(scanner) do
      # TODO: Need `scanner.build_target` to take a String
      # or something to be able to test things like this.
      # Or... maybe this is your escape hatch?
      target = SecTester::Target.new(Lucky::AssetHelpers.asset("js/app.js"))
      scanner.run_check(
        scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
        tests: "retire_js",
        target: target
      )
    end
  end
end

private def scanner
  LuckySecTester.new
end

private def with_cleanup(tester : LuckySecTester)
  yield
ensure
  tester.try &.cleanup
end
