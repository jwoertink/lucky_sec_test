require "./shards"

# Load the asset manifest in public/mix-manifest.json
Lucky::AssetHelpers.load_manifest

require "./app_database"
require "./models/base_model"
require "./models/mixins/**"
require "./models/**"
require "./queries/mixins/**"
require "./queries/**"
require "./operations/mixins/**"
require "./operations/**"
require "./serializers/base_serializer"
require "./serializers/**"
require "./emails/base_email"
require "./emails/**"
require "./actions/mixins/**"
require "./actions/**"
require "./components/base_component"
require "./components/**"
require "./pages/**"
require "../config/server"
require "../config/**"
require "../db/migrations/**"
require "./app_server"

module Lucky::ProtectFromForgery
  Habitat.create do
    setting allow_forgery_protection : Bool = true
  end

  private def protect_from_forgery
    set_session_csrf_token
    if !settings.allow_forgery_protection? || request_does_not_require_protection? || valid_csrf_token?
      continue
    else
      forbid_access_because_of_bad_token
    end
  end
end
