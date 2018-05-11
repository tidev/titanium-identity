<h1 align="center">🔐 Ti.Identity</h1>

<p align="center">This native module allows you to use Fingerprint authentication, Keychain Access and Face authentication (iOS) with Axway Titanium.</p>

## Requirements
- Titanium SDK 6.2.0 or later
- iOS 8.0 or later
- Xcode 8 or later

## Features
- [x] Use the Fingerprint sensor of your device to authenticate
- [x] Use the Face detection API's of your device to authenticate (iOS 11+)
- [x] Store, read, update and delete items with the native keychain

## Example
Please see the full-featured example in `ios/example/app.js` and `ios/example/app.js`.

## Build from Source
- iOS: `appc run -p ios --build-only` from the `ios` directory
- Android: `appc run -p android --build-only` from the `android` directory

> Note: Please do not use the (deprecated) `build.py` for iOS and `ant` for Android anymore.
> Those are unified in the above appc-cli these days.

## Author
Hans Knöchel, Axway

## License
Apache 2.0

## Contributing
Code contributions are greatly appreciated, please submit a new [pull request](https://github.com/appcelerator-modules/titanium-identity/pull/new/master)!
