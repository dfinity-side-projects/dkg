# SYNOPSIS 
[![NPM Package](https://img.shields.io/npm/v/dkg.svg?style=flat-square)](https://www.npmjs.org/package/dkg)
[![Build Status](https://img.shields.io/travis/wanderer/dkg.svg?branch=master&style=flat-square)](https://travis-ci.org/wanderer/dkg)
[![Coverage Status](https://img.shields.io/coveralls/wanderer/dkg.svg?style=flat-square)](https://coveralls.io/r/wanderer/dkg)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)  

[Distributed key generation](https://en.wikipedia.org/wiki/Distributed_key_generation) primitives in JS. With this you can create a "group" with a threshold that has a shared secert and a public key for the group. This group can then sign on messages and when the threshold number of members sign anyone can create recover the groups signture on the message which can be validated against the groups public key. The signiture is also determinist no matter which members on the message.

# INSTALL
`npm install dkg`

# USAGE
[./example.js](./example.js)

# API
[./docs/](./docs/index.md)

# LICENSE
[MPL-2.0](https://tldrlegal.com/license/mozilla-public-license-2.0-(mpl-2))
