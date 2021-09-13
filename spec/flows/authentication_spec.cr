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

  # Testing the auth page with bruteforce attack
  it "doesn't sign in through bruteforce attack" do
    tester = SecTester::Test.new
    tester.run_check(
      scan_name: "UnitTestingScan - BFL",
      test_name: "bfl",
      target: SecTester::Target.new("http://#{ENV["LUCKY_ENV"]}:#{ENV["DEV_PORT"]}/sign_up")
    )
  end
end

private def should_be_signed_in(flow)
  flow.el("@nav-sign-out-button").should be_on_page
end
