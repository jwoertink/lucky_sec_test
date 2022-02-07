class Application
  Habitat.create do
    setting name : String
    setting support_email : Carbon::Address
  end
end

Application.configure do |settings|
  settings.name = "Lucky SecTest"
  settings.support_email = Carbon::Address.new(settings.name, "no-reply@lucky_sectest.com")
end

Lucky::ProtectFromForgery.configure do |config|
  config.allow_forgery_protection = false
end
