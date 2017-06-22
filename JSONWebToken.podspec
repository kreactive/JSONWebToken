
Pod::Spec.new do |s|
s.name         = 'JSONWebToken'
s.version      = '2.0'
s.summary      = 'Swift lib for decoding, validating, signing and verifying JWT'
s.homepage     = "https://github.com/kreactive/JSONWebToken"
s.license      = { :type => 'MIT', :file => 'LICENSE' }
s.author       = { 'Kreactive' => 'https://github.com/kreactive' }
s.source       = { :git => "https://github.com/kreactive/JSONWebToken.git" }


s.ios.deployment_target = '9.0'
s.requires_arc = true
s.framework    = 'Security'
s.source_files = "JSONWebToken/*.{swift,h,m}"
s.pod_target_xcconfig =  {
    'swift_version' => '4.0',
}
end

