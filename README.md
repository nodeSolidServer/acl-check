# acl-check

[![](https://img.shields.io/badge/project-Solid-7C4DFF.svg?style=flat)](https://github.com/solid/solid)
[![NPM Version](https://img.shields.io/npm/v/acl-check.svg?style=flat)](https://npm.im/acl-check)
[![Build Status](https://travis-ci.org/solid/acl-check.svg?branch=master)](https://travis-ci.org/solid/acl-check)

Javascript library for checking [Web Access
Control](https://github.com/solid/web-access-control-spec) ACLs.

## Usage

```js
const $rdf = require('rdflib')
const aclCheck = require('acl-check')
const ACL = $rdf.Namespace('http://www.w3.org/ns/auth/acl#')

const kb = $rdf.graph()
const fetcher = $rdf.fetcher(kb)

let doc = $rdf.sym('https://alice.example.com/stuff/myVacation.ttl')
let aclDoc = $rdf.sym('https://alice.example.com/stuff/myVacation.ttl.acl')
let directory = $rdf.sym('https://alice.example.com/stuff/')
let dirAclDoc = $rdf.sym('https://alice.example.com/stuff/')

let agent = $rdf.sym('https://alice.example.com/card.ttl#me')
let modesRequired = [ ACL('Read'), ACL('Write'), ACL('Control') ]

await fetcher.load(aclDoc) // Load the ACL documents into kb

let allow = aclCheck.checkAccess(kb, resource, null, aclDoc, agent, modesRequired, origin, trustedOrigins)

// When there is no direct ACL file, find the closest container ACL file in the tree above then...
await fetcher.load(dirAclDoc) // Load the directory ACL documents into kb
let allow = aclCheck.checkAccess(kb, resource, directory, dirAclDoc, agent, modesRequired, origin, trustedOrigins)

console.log('Access allowed? ' + allow)
// OWTTE
```
