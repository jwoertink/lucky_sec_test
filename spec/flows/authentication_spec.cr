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
  it "doesn't sign in through SQLi attack" do
    tester = SecTester::Test.new
    tester.run_check(
      scan_name: "UnitTestingScan - SQLi",
      test_name: "sqli",
      target: SecTester::Target.new(
        method: "POST",
        url: "http://localhost:#{ENV["DEV_PORT"]}/sign_in",
        headers: HTTP::Headers{
          "Content-Type" => "application/x-www-form-urlencoded",
          "Host"         => "localhost:#{ENV["DEV_PORT"]}",
        },
        body: "_csrf=0AU9Vu9YSF_YH2I92O4apuvsCYRuPOnKVet1KFTQE6M&user%3Aemail=test%40test.com&user%3Apassword=1234"
      )
    )
  ensure
    tester.try &.cleanup
  end

  # Testing the auth page with Dom XSS attack
  it "doesn't sign in through Dom XSS attack" do
    tester = SecTester::Test.new
    tester.run_check(
      scan_name: "UnitTestingScan - Dom XSS",
      test_name: "dom_xss",
      target: SecTester::Target.new("http://localhost:#{ENV["DEV_PORT"]}/sign_in")
    )
  ensure
    tester.try &.cleanup
  end

  # Testing the auth page with Dom XSS attack
  it "doesn't sign in through Dom XSS attack" do
    tester = SecTester::Test.new
    tester.run_check(
      scan_name: "UnitTestingScan - Dom XSS",
      test_name: "dom_xss",
      target: SecTester::Target.new("http://localhost:#{ENV["DEV_PORT"]}/sign_up")
    )
  ensure
    tester.try &.cleanup
  end
end

private def should_be_signed_in(flow)
  flow.el("@nav-sign-out-button").should be_on_page
end
