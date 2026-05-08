require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-mqtt-client"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]


  s.platforms    = { :ios => "15.1" }
  s.source       = { :git => "https://github.com/arduino/react-native-mqtt-client.git", :tag => "#{s.version}" }


  s.source_files = "ios/**/*.{h,m,mm,swift}"


  s.dependency "React"
  s.dependency "CocoaMQTT", "= 2.2.4"
  s.dependency "CocoaMQTT/WebSockets", "= 2.2.4"
  s.dependency "Starscream", "= 4.0.8"
end
