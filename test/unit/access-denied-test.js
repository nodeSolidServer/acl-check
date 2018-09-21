'use strict'

const test = require('tape')
const aclLogic = require('../../src/acl-check')
const $rdf = require('rdflib')

const ACL = $rdf.Namespace('http://www.w3.org/ns/auth/acl#')
const FOAF = $rdf.Namespace('http://xmlns.com/foaf/0.1/')

const prefixes = `@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/>.
@prefix alice: <https://alice.example.com/#>.
@prefix bob: <https://bob.example.com/#>.
`
const alice = $rdf.sym('https://alice.example.com/#me')
const bob = $rdf.sym('https://bob.example.com/#me')
const malory = $rdf.sym('https://someone.else.example.com/')

// Append access implied by Write acecss
test('aclCheck checkAccess() test - Append access implied by Write acecss', t => {
  let resource = $rdf.sym('https://alice.example.com/docs/file1')
  let aclUrl = 'https://alice.example.com/docs/.acl'
  let aclDoc = $rdf.sym(aclUrl)

  const store = $rdf.graph() // Quad store
  const ACLtext = prefixes +
  ` <#auth> a acl:Authorization;
    acl:mode acl:Write;
    acl:agent alice:me;
    acl:accessTo <${resource.uri}> .
  `
  $rdf.parse(ACLtext, store, aclUrl, 'text/turtle')

  const agent = alice
  const directory = null
  const modesRequired = [ ACL('Append')]
  const trustedOrigins = null
  const origin = null

  const result = !aclLogic.accessDenied(store, resource, directory, aclDoc, agent, modesRequired, origin, trustedOrigins)
  t.ok(result, 'Alice should have Append access implied by Write access')
  t.end()
})

// Straight ACL access test
test('acl-check checkAccess() test - accessTo', function (t) {
  let container = $rdf.sym('https://alice.example.com/docs/')
  let containerAclUrl = 'https://alice.example.com/docs/.acl'
  let containerAcl = $rdf.sym(containerAclUrl)

  const store = $rdf.graph() // Quad store
  const ACLtext = prefixes +
  ` <#auth> a acl:Authorization;
    acl:mode acl:Read, acl:Write;
    acl:agent alice:me;
    acl:accessTo <${container.uri}> .
  `
  $rdf.parse(ACLtext, store, containerAclUrl, 'text/turtle')

  var result = aclLogic.accessDenied(store, container, null, containerAcl, bob, [ ACL('Write')])
  t.ok(result, 'Bob Should not have access')

  t.end()
})

// Inheriting permissions from directory defaults
test('acl-check checkAccess() test - default/inherited', function (t) {
  let container = $rdf.sym('https://alice.example.com/docs/')
  let containerAcl = $rdf.sym('https://alice.example.com/docs/.acl')
  let file1 = $rdf.sym('https://alice.example.com/docs/file1')
  let file2 = $rdf.sym('https://alice.example.com/docs/stuff/file2')
  var result
  const store = $rdf.graph()
  /*
  let ACLtext = prefixes + ` <#auth> a acl:Authorization;
    acl:mode acl:Read;
    acl:agent bob:me;
    acl:accessTo <${file1.uri}> .
`
  $rdf.parse(ACLtext, store, containerAcl.uri, 'text/turtle')
*/
  let containerAclText = prefixes + ` <#auth> a acl:Authorization;
      acl:mode acl:Read;
      acl:agent alice:me;
      acl:default <${container.uri}> .
`
  $rdf.parse(containerAclText, store, containerAcl.uri, 'text/turtle')

  result = !aclLogic.accessDenied(store, file1, container, containerAcl, alice, [ ACL('Read')])
  t.ok(result, 'Alice should have Read acces inherited')

  result = !aclLogic.accessDenied(store, file2, container, containerAcl, alice, [ ACL('Read')])
  t.ok(result, 'Alice should have Read acces inherited 2')

  result = aclLogic.accessDenied(store, file2, container, containerAcl, alice, [ ACL('Write')])
  t.ok(result, 'Alice should NOT have Write acces inherited')

  t.end()
})



// Inheriting permissions from directory defaults
test('acl-check checkAccess() test - default/inherited', function (t) {
  let container = $rdf.sym('https://alice.example.com/docs/')
  let containerAcl = $rdf.sym('https://alice.example.com/docs/.acl')
  let file1 = $rdf.sym('https://alice.example.com/docs/file1')
  let file2 = $rdf.sym('https://alice.example.com/docs/stuff/file2')
  var result
  const store = $rdf.graph()
  /*
  let ACLtext = prefixes + ` <#auth> a acl:Authorization;
    acl:mode acl:Read;
    acl:agent bob:me;
    acl:accessTo <${file1.uri}> .
    `
  $rdf.parse(ACLtext, store, containerAcl.uri, 'text/turtle')
*/
  let containerAclText = prefixes + ` <#auth> a acl:Authorization;
      acl:mode acl:Read;
      acl:agentClass foaf:Agent;
      acl:default <${container.uri}> .
`
  $rdf.parse(containerAclText, store, containerAcl.uri, 'text/turtle')
  console.log('@@' + containerAclText + '@@@')

  result = aclLogic.accessDenied(store, file2, container, containerAcl, alice, [ ACL('Write')])
  t.ok(result, 'Alice should NOT have write acces inherited  - Public')

  t.end()
})

////////////////////////////  Non-anonymoud versions
// Append access implied by Write acecss -PUBLIC
test('aclCheck checkAccess() test - Append access implied by Public Write acecss', t => {
  let resource = $rdf.sym('https://alice.example.com/docs/file1')
  let aclUrl = 'https://alice.example.com/docs/.acl'
  let aclDoc = $rdf.sym(aclUrl)

  const store = $rdf.graph() // Quad store
  const ACLtext = prefixes +
  ` <#auth> a acl:Authorization;
    acl:mode acl:Write;
    acl:agentClass acl:AuthenticatedAgent;
    acl:accessTo <${resource.uri}> .
  `
  $rdf.parse(ACLtext, store, aclUrl, 'text/turtle')

  const modesRequired = [ ACL('Append')]

  let result = aclLogic.checkAccess(store, resource, null, aclDoc, alice, modesRequired)
  t.ok(result, 'Alice should have Append access implied by Write access - AuthenticatedAgent')

  t.end()
})

// Straight ACL access test
test('acl-check checkAccess() test - accessTo', function (t) {
  let container = $rdf.sym('https://alice.example.com/docs/')
  let containerAclUrl = 'https://alice.example.com/docs/.acl'
  let containerAcl = $rdf.sym(containerAclUrl)

  const store = $rdf.graph() // Quad store
  const ACLtext = prefixes +
  ` <#auth> a acl:Authorization;
    acl:mode acl:Read, acl:Write;
    acl:agentClass acl:AuthenticatedAgent;
    acl:accessTo <${container.uri}> .
  `
  $rdf.parse(ACLtext, store, containerAclUrl, 'text/turtle')

  var result = aclLogic.accessDenied(store, container, null, containerAcl, null, [ ACL('Read')])
  t.ok(result, 'Anonymous should NOT have Read acces to public thing - AuthenticatedAgent')

  result = aclLogic.accessDenied(store, container, null, containerAcl, null, [ ACL('Write')])
  t.ok(result, 'Anonymous should NOT have Write acces - AuthenticatedAgent')

  result = !aclLogic.accessDenied(store, container, null, containerAcl, bob, [ ACL('Write')])
  t.ok(result, 'Bob should have Write acces to public write - AuthenticatedAgent')

  t.end()
})

// Inheriting permissions from directory defaults
test('acl-check checkAccess() test - default/inherited', function (t) {
  let container = $rdf.sym('https://alice.example.com/docs/')
  let containerAcl = $rdf.sym('https://alice.example.com/docs/.acl')
  let file1 = $rdf.sym('https://alice.example.com/docs/file1')
  let file2 = $rdf.sym('https://alice.example.com/docs/stuff/file2')
  var result
  const store = $rdf.graph()
  let ACLtext = prefixes + ` <#auth> a acl:Authorization;
    acl:mode acl:Read;
    acl:agent bob:me;
    acl:accessTo <${file1.uri}> .
`
  $rdf.parse(ACLtext, store, containerAcl.uri, 'text/turtle')

  let containerAclText = prefixes + ` <#auth> a acl:Authorization;
      acl:mode acl:Read;
      acl:agentClass acl:AuthenticatedAgent;
      acl:default <${container.uri}> .
`
  $rdf.parse(containerAclText, store, containerAcl.uri, 'text/turtle')

  result = aclLogic.accessDenied(store, file2, container, containerAcl, alice, [ ACL('Write')])
  t.ok(result, 'Alice should NOT have write acces inherited  - AuthenticatedAgent')

  t.end()
})
