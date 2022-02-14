require "../spec_helper"

describe "Authentication flow" do
  it "works" do
    flow = AuthenticationFlow.new("test@example.com")

    flow.sign_up "password"
    flow.should_be_on_sign_in_page
    flow.should_send_confirmation_email
    flow.sign_in "password"
    flow.should_have_confirmation_error
    flow.confirm_user
    flow.sign_in "wrong-password"
    flow.should_have_password_error
    flow.sign_in "password"
    flow.should_be_signed_in
  end

  # This is to show you how to sign in as a user during tests.
  # Use the `visit` method's `as` option in your tests to sign in as that user.
  #
  # Feel free to delete this once you have other tests using the 'as' option.
  it "allows sign in through backdoor when testing" do
    user = UserFactory.create
    flow = BaseFlow.new

    flow.visit Me::Edit, as: user
    should_be_signed_in(flow)
  end

  # Testing the auth page with SQLi attack
  it "Testing sign_in page for SQLi, OSI, XSS attacks" do
    tester = SecTester::Test.new
    tester.run_check(
      scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
      tests: [
        "sqli",
        "osi",
        "xss",
      ],
      target: SecTester::Target.new(
        method: "POST",
        url: "http://localhost:#{ENV["DEV_PORT"]}/sign_in",
        headers: HTTP::Headers{
          "Content-Type" => "application/x-www-form-urlencoded",
          "Host"         => "localhost:#{ENV["DEV_PORT"]}",
        },
        body: "user%3Aemail=test%40test.com&user%3Apassword=1234"
      )
    )
  ensure
    tester.try &.cleanup
  end

  it "Testing sign_up page for SQLi, OSI, XSS attacks" do
    tester = SecTester::Test.new
    tester.run_check(
      scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
      tests: [
        "sqli",
        "osi",
        "xss",
      ],
      target: SecTester::Target.new(
        method: "POST",
        url: "http://localhost:#{ENV["DEV_PORT"]}/sign_in",
        headers: HTTP::Headers{
          "Content-Type" => "application/x-www-form-urlencoded",
          "Host"         => "localhost:#{ENV["DEV_PORT"]}",
        },
        body: "user%3Aemail=aa%40aa.com&user%3Apassword=123456789&user%3Apassword_confirmation=123456789"
      )
    )
  ensure
    tester.try &.cleanup
  end

  # Testing the auth page with Dom XSS attack
  it "Testing sign_in for dom based XSS" do
    tester = SecTester::Test.new
    tester.run_check(
      scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
      tests: "dom_xss",
      target: SecTester::Target.new("http://localhost:#{ENV["DEV_PORT"]}/sign_in")
    )
  ensure
    tester.try &.cleanup
  end

  # Testing the auth page with Dom XSS attack
  it "testing sign_up for dom based XSS" do
    tester = SecTester::Test.new
    tester.run_check(
      scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
      tests: "dom_xss",
      target: SecTester::Target.new("http://localhost:#{ENV["DEV_PORT"]}/sign_up")
    )
  ensure
    tester.try &.cleanup
  end

  # Testing the auth page with Headers Security attack
  it "testing root for header security issues" do
    tester = SecTester::Test.new
    tester.run_check(
      scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
      tests: "header_security",
      target: SecTester::Target.new("http://localhost:#{ENV["DEV_PORT"]}/")
    )
  ensure
    tester.try &.cleanup
  end

  # Testing the auth page with Cookies Security attack
  it "testing root for cookie security issues" do
    tester = SecTester::Test.new
    tester.run_check(
      scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
      tests: "cookie_security",
      target: SecTester::Target.new("http://localhost:#{ENV["DEV_PORT"]}/")
    )
  ensure
    tester.try &.cleanup
  end

  # Testing JS file for 3rd party issues
  it "Tests /js/app.js for 3rd party issues" do
    tester = SecTester::Test.new
    tester.run_check(
      scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
      tests: "retire_js",
      target: SecTester::Target.new("http://localhost:#{ENV["DEV_PORT"]}/js/app.js")
    )
  ensure
    tester.try &.cleanup
  end
end

private def should_be_signed_in(flow)
  flow.el("@nav-sign-out-button").should be_on_page
end
