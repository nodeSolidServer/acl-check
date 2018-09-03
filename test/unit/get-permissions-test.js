'use strict'

const test = require('tape')
const rdf = require('rdflib')
const PermissionSet = require('../../src/permission-set')
const SolidResponse = require('solid-web-client/lib/models/response')

const acls = require('../../src/index')  // solid-permissions module

const resourceUrl = 'https://example.com/resource1'
const webId = 'https://example.com/#me'

const aclSource = `@prefix acl: <http://www.w3.org/ns/auth/acl#>.
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
<#authorization>
    acl:agent <https://example.com/#me>;
    acl:accessTo <https://example.com/resource1>;
    acl:mode acl:Read, acl:Write, acl:Control.`

const mockWebClient = {
  head: (url) => {
    let response = new SolidResponse()
    response.rdf = rdf
    response.url = url
    response.acl = 'resource1.acl'
    return Promise.resolve(response)
  },
  get: (url) => {
    let response = new SolidResponse()
    response.rdf = rdf
    response.url = url
    response.xhr = {
      response: aclSource
    }
    response.contentType = () => { return 'text/turtle' }
    return Promise.resolve(response)
  }
}

test('getPermissions() test', t => {
  acls.getPermissions(resourceUrl, mockWebClient, rdf)
    .then(permissionSet => {
      t.ok(permissionSet instanceof PermissionSet,
        'Result should be a PermissionSet instance')
      permissionSet.checkAccess(resourceUrl, webId, 'READ')
        .then(hasAccess => {
          t.ok(hasAccess, 'User should have READ access')
          t.end()
        })
    })
    .catch(err => {
      console.log(err)
      t.fail()
    })
})
