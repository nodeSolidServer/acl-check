'use strict'

const test = require('tape')
// const Authorization = require('../../src/authorization')
// const { acl } = require('../../src/modes')
// const PermissionSet = require('../../src/permission-set')
const aclLogic = require('../../src/acl-check')
const $rdf = require('rdflib')

const ACL = $rdf.Namespace('http://www.w3.org/ns/auth/acl#')
const FOAF = $rdf.Namespace('http://xmlns.com/foaf/0.1/')

const prefixes = `@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/>.
@prefix alice: <https://alice.example.com/>.
@prefix bob: <https://bob.example.com/#>.
`
const aliceWebId = 'https://alice.example.com/#me'
const alice = $rdf.sym('https://alice.example.com/#me')
const bob = $rdf.sym('https://bob.example.com/#me')
const malory = $rdf.sym('https://someone.else.example.com/')

// Append access implied by Write acecss
test('aclCheck checkAccess() test - Append access implied by Write acecss', t => {
  let resource = $rdf.sym('https://alice.example.com/docs/file1')
  let aclUrl = 'https://alice.example.com/docs/.acl'
  let aclDoc = $rdf.sym(aclUrl)

  const kb = $rdf.graph() // Quad store
  const ACLtext = prefixes +
  ` <#auth> a acl:Authorization;
    acl:mode acl:Read;
    acl:agent alice:me;
    acl:accessTo <${resource.uri}> .
  `
  $rdf.parse(ACLtext, kb, aclUrl, 'text/turtle')

  const agent = alice
  const directory = null
  const modesRequired = [ ACL('Append')]
  const trustedOrigins = null
  const origin = null

  const result = aclLogic.checkAccess(kb, resource, directory, aclDoc, agent, modesRequired, origin, trustedOrigins)
  if (result) {
    t.ok(result, 'Alice should have Append access implied by Write access')
  } else {
    t.fail('Alice should have Append access implied by Write access')
  }
  t.end()
})

// Straight ACL access test
test('acl-check checkAccess() test - accessTo', function (t) {
  let container = $rdf.sym('https://alice.example.com/docs/')
  let containerAclUrl = 'https://alice.example.com/docs/.acl'
  let containerAcl = $rdf.sym(containerAclUrl)

  const kb = $rdf.graph() // Quad store
  const ACLtext = prefixes +
  ` <#auth> a acl:Authorization;
    acl:mode acl:Read, acl:Write;
    acl:agent alice:me;
    acl:accessTo <${container.uri}> .
  `
  $rdf.parse(ACLtext, kb, containerAclUrl, 'text/turtle')

  var result = aclLogic.checkAccess(kb, container, null, containerAcl, alice, [ ACL('Read')])
  if (result) {
    t.ok(result, 'Alice should have Read acces')
  } else {
    t.fail('Alice s....')
  }

  result = aclLogic.checkAccess(kb, container, null, containerAcl, alice, [ ACL('Write')])
  if (result) {
    t.ok(result, 'Alice should have Write acces')
  } else {
    t.fail('Alice s....')
  }

  result = aclLogic.checkAccess(kb, container, null, containerAcl, bob, [ ACL('Write')])
  if (!result) {
    t.ok(result, 'Bob should not have Write acces')
  } else {
    t.fail('Alice s....')
  }

  t.end()
})

// Inheriting permissions from directory defaults
test('acl-check checkAccess() test - default/inherited', function (t) {
  let container = $rdf.sym('https://alice.example.com/docs/')
  let containerAcl = $rdf.sym('https://alice.example.com/docs/.acl')
  let file1 = $rdf.sym('https://alice.example.com/docs/file1')
  let file2 = $rdf.sym('https://alice.example.com/docs/stuff/file2')
  var result
  const kb = $rdf.graph()
  let ACLtext = prefixes + ` <#auth> a acl:Authorization;
    acl:mode acl:Read;
    acl:agent bob:me;
    acl:accessTo <${file1.uri}> .
`
  $rdf.parse(ACLtext, kb, containerAcl.uri, 'text/turtle')

  let containerAclText = prefixes + ` <#auth> a acl:Authorization;
      acl:mode acl:Read;
      acl:agent alice:me;
      acl:default <${container.uri}> .
`
  $rdf.parse(containerAclText, kb, containerAcl.uri, 'text/turtle')

  result = aclLogic.checkAccess(kb, file1, container, containerAcl, alice, [ ACL('Read')])
  if (result) {
    t.ok(result, 'Alice should have Read acces inherited')
  } else {
    t.fail('Alice s....')
  }

  result = aclLogic.checkAccess(kb, file2, container, containerAcl, alice, [ ACL('Read')])
  if (result) {
    t.ok(result, 'Alice should have Read acces inherited 2')
  } else {
    t.fail('Alice s....')
  }

  result = aclLogic.checkAccess(kb, file2, container, containerAcl, alice, [ ACL('Read')])
  if (result) {
    t.ok(result, 'Mallory should NOT have Read acces inherited')
  } else {
    t.fail('Alice s....')
  }

  t.end()
})

// Public access VESRIONS OF THESE
// Append access implied by Write acecss -PUBLIC
test('aclCheck checkAccess() test - Append access implied by Public Write acecss', t => {
  let resource = $rdf.sym('https://alice.example.com/docs/file1')
  let aclUrl = 'https://alice.example.com/docs/.acl'
  let aclDoc = $rdf.sym(aclUrl)

  const kb = $rdf.graph() // Quad store
  const ACLtext = prefixes +
  ` <#auth> a acl:Authorization;
    acl:mode acl:Read;
    acl:agentClass foaf:Agent;
    acl:accessTo <${resource.uri}> .
  `
  $rdf.parse(ACLtext, kb, aclUrl, 'text/turtle')

  const agent = alice
  const directory = null
  const modesRequired = [ ACL('Append')]
  const trustedOrigins = null
  const origin = null

  const result = aclLogic.checkAccess(kb, resource, directory, aclDoc, agent, modesRequired, origin, trustedOrigins)
  if (result) {
    t.ok(result, 'Alice should have Append access implied by Write access')
  } else {
    t.fail('Alice should have Append access implied by Write access')
  }
  t.end()
})

// Straight ACL access test
test('acl-check checkAccess() test - accessTo', function (t) {
  let container = $rdf.sym('https://alice.example.com/docs/')
  let containerAclUrl = 'https://alice.example.com/docs/.acl'
  let containerAcl = $rdf.sym(containerAclUrl)

  const kb = $rdf.graph() // Quad store
  const ACLtext = prefixes +
  ` <#auth> a acl:Authorization;
    acl:mode acl:Read, acl:Write;
    acl:agentClass foaf:Agent;
    acl:accessTo <${container.uri}> .
  `
  $rdf.parse(ACLtext, kb, containerAclUrl, 'text/turtle')

  var result = aclLogic.checkAccess(kb, container, null, containerAcl, alice, [ ACL('Read')])
  if (result) {
    t.ok(result, 'Alice should have Read acces')
  } else {
    t.fail('Alice s....')
  }

  result = aclLogic.checkAccess(kb, container, null, containerAcl, alice, [ ACL('Write')])
  if (result) {
    t.ok(result, 'Alice should have Write acces')
  } else {
    t.fail('Alice s....')
  }

  result = aclLogic.checkAccess(kb, container, null, containerAcl, bob, [ ACL('Write')])
  if (!result) {
    t.ok(result, 'Bob should not have Write acces')
  } else {
    t.fail('Alice s....')
  }

  t.end()
})

// Inheriting permissions from directory defaults
test('acl-check checkAccess() test - default/inherited', function (t) {
  let container = $rdf.sym('https://alice.example.com/docs/')
  let containerAcl = $rdf.sym('https://alice.example.com/docs/.acl')
  let file1 = $rdf.sym('https://alice.example.com/docs/file1')
  let file2 = $rdf.sym('https://alice.example.com/docs/stuff/file2')
  var result
  const kb = $rdf.graph()
  let ACLtext = prefixes + ` <#auth> a acl:Authorization;
    acl:mode acl:Read;
    acl:agent bob:me;
    acl:accessTo <${file1.uri}> .
`
  $rdf.parse(ACLtext, kb, containerAcl.uri, 'text/turtle')

  let containerAclText = prefixes + ` <#auth> a acl:Authorization;
      acl:mode acl:Read;
      acl:agentClass foaf:Agent;
      acl:default <${container.uri}> .
`
  $rdf.parse(containerAclText, kb, containerAcl.uri, 'text/turtle')

  result = aclLogic.checkAccess(kb, file1, container, containerAcl, alice, [ ACL('Read')])
  if (result) {
    t.ok(result, 'Alice should have Read acces inherited')
  } else {
    t.fail('Alice s....')
  }

  result = aclLogic.checkAccess(kb, file2, container, containerAcl, alice, [ ACL('Read')])
  if (result) {
    t.ok(result, 'Alice should have Read acces inherited 2')
  } else {
    t.fail('Alice s....')
  }

  result = aclLogic.checkAccess(kb, file2, container, containerAcl, alice, [ ACL('Read')])
  if (result) {
    t.ok(result, 'Mallory should NOT have Read acces inherited')
  } else {
    t.fail('Alice s....')
  }

  t.end()
})
