'use strict'

const test = require('tape')
// const Authorization = require('../../src/authorization')
// const { acl } = require('../../src/modes')
// const PermissionSet = require('../../src/permission-set')
const aclLogic = require('../../src/acl-check')
const $rdf = require('rdflib')

const ACL = $rdf.Namespace('http://www.w3.org/ns/auth/acl#')
const FOAF = $rdf.Namespace('http://xmlns.com/foaf/0.1/')
const ALICE = $rdf.Namespace('https://alice.example.com/')

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
  const resource = $rdf.sym('https://alice.example.com/docs/file1')
  const aclUrl = 'https://alice.example.com/docs/.acl'
  const aclDoc = $rdf.sym(aclUrl)

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
  const modesRequired = [ACL('Append')]
  const trustedOrigins = null
  const origin = null

  const result = aclLogic.checkAccess(store, resource, directory, aclDoc, agent, modesRequired, origin, trustedOrigins)
  t.ok(result, 'Alice should have Append access implied by Write access')
  t.end()
})

// Straight ACL access test
test('acl-check checkAccess() test - accessTo', function (t) {
  const container = $rdf.sym('https://alice.example.com/docs/')
  const containerAclUrl = 'https://alice.example.com/docs/.acl'
  const containerAcl = $rdf.sym(containerAclUrl)

  const store = $rdf.graph() // Quad store
  const ACLtext = prefixes +
  ` <#auth> a acl:Authorization;
    acl:mode acl:Read, acl:Write;
    acl:agent alice:me;
    acl:accessTo <${container.uri}> .
  `
  $rdf.parse(ACLtext, store, containerAclUrl, 'text/turtle')

  var result = aclLogic.checkAccess(store, container, null, containerAcl, alice, [ACL('Read')])
  t.ok(result, 'Alice should have Read acces')

  result = aclLogic.checkAccess(store, container, null, containerAcl, alice, [ACL('Write')])
  t.ok(result, 'Alice should have Write acces')

  result = !aclLogic.checkAccess(store, container, null, containerAcl, bob, [ACL('Write')])
  t.ok(result, 'Bob Should not have access')

  t.end()
})

// Inheriting permissions from directory defaults
test('acl-check checkAccess() test - default/inherited', function (t) {
  const container = $rdf.sym('https://alice.example.com/docs/')
  const containerAcl = $rdf.sym('https://alice.example.com/docs/.acl')
  const file1 = $rdf.sym('https://alice.example.com/docs/file1')
  const file2 = $rdf.sym('https://alice.example.com/docs/stuff/file2')
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
  const containerAclText = prefixes + ` <#auth> a acl:Authorization;
      acl:mode acl:Read;
      acl:agent alice:me;
      acl:default <${container.uri}> .
`
  $rdf.parse(containerAclText, store, containerAcl.uri, 'text/turtle')

  result = aclLogic.checkAccess(store, file1, container, containerAcl, alice, [ACL('Read')])
  t.ok(result, 'Alice should have Read access inherited')

  result = aclLogic.checkAccess(store, file2, container, containerAcl, alice, [ACL('Read')])
  t.ok(result, 'Alice should have Read access inherited 2')

  result = !aclLogic.checkAccess(store, file2, container, containerAcl, alice, [ACL('Write')])
  t.ok(result, 'Alice should NOT have Write access inherited')

  t.end()
})

// Inheriting permissions from directory defaults -- OLD version defaultForNew
test('acl-check checkAccess() test - default/inherited', function (t) {
  const container = $rdf.sym('https://alice.example.com/docs/')
  const containerAcl = $rdf.sym('https://alice.example.com/docs/.acl')
  const file1 = $rdf.sym('https://alice.example.com/docs/file1')
  const file2 = $rdf.sym('https://alice.example.com/docs/stuff/file2')
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
  const containerAclText = prefixes + ` <#auth> a acl:Authorization;
      acl:mode acl:Read;
      acl:agent alice:me;
      acl:defaultForNew <${container.uri}> .
`
  $rdf.parse(containerAclText, store, containerAcl.uri, 'text/turtle')

  result = aclLogic.checkAccess(store, file1, container, containerAcl, alice, [ACL('Read')])
  t.ok(result, 'Alice should have Read access inherited')

  result = aclLogic.checkAccess(store, file2, container, containerAcl, alice, [ACL('Read')])
  t.ok(result, 'Alice should have Read access inherited 2')

  result = !aclLogic.checkAccess(store, file2, container, containerAcl, alice, [ACL('Write')])
  t.ok(result, 'Alice should NOT have Write access inherited')

  result = !aclLogic.checkAccess(store, file2, container, containerAcl, alice, [ACL('Write'), ACL('Read')])
  t.ok(result, 'Alice should NOT have Read and Write access inherited')

  t.end()
})

/// ////////////////////////////////////// Public access VESRIONS OF THESE
// Append access implied by Write acecss -PUBLIC
test('aclCheck checkAccess() test - Append access implied by Public Write acecss', t => {
  const resource = $rdf.sym('https://alice.example.com/docs/file1')
  const aclUrl = 'https://alice.example.com/docs/.acl'
  const aclDoc = $rdf.sym(aclUrl)

  const store = $rdf.graph() // Quad store
  const ACLtext = prefixes +
  ` <#auth> a acl:Authorization;
    acl:mode acl:Write;
    acl:agentClass foaf:Agent;
    acl:accessTo <${resource.uri}> .
  `
  $rdf.parse(ACLtext, store, aclUrl, 'text/turtle')

  const modesRequired = [ACL('Append')]

  const result = aclLogic.checkAccess(store, resource, null, aclDoc, alice, modesRequired)
  t.ok(result, 'Alice should have Append access implied by Write access - Public')

  t.end()
})

// Straight ACL access test
test('acl-check checkAccess() test - accessTo', function (t) {
  const container = $rdf.sym('https://alice.example.com/docs/')
  const containerAclUrl = 'https://alice.example.com/docs/.acl'
  const containerAcl = $rdf.sym(containerAclUrl)

  const store = $rdf.graph() // Quad store
  const ACLtext = prefixes +
  ` <#auth> a acl:Authorization;
    acl:mode acl:Read, acl:Write;
    acl:agentClass foaf:Agent;
    acl:accessTo <${container.uri}> .
  `
  $rdf.parse(ACLtext, store, containerAclUrl, 'text/turtle')

  var result = aclLogic.checkAccess(store, container, null, containerAcl, alice, [ACL('Read')])
  t.ok(result, 'Alice should have Read access - Public')

  result = aclLogic.checkAccess(store, container, null, containerAcl, alice, [ACL('Write')])
  t.ok(result, 'Alice should have Write acces')

  var result = aclLogic.checkAccess(store, container, null, containerAcl, null, [ACL('Read')])
  t.ok(result, 'Anonymous should have Read access to public thing - Public')

  result = aclLogic.checkAccess(store, container, null, containerAcl, null, [ACL('Write')])
  t.ok(result, 'Anonymous should have Write access - Public')

  result = aclLogic.checkAccess(store, container, null, containerAcl, bob, [ACL('Write')])
  t.ok(result, 'Bob should have Write access to public write - Public')

  t.end()
})

// Inheriting permissions from directory defaults
test('acl-check checkAccess() test - default/inherited', function (t) {
  const container = $rdf.sym('https://alice.example.com/docs/')
  const containerAcl = $rdf.sym('https://alice.example.com/docs/.acl')
  const file1 = $rdf.sym('https://alice.example.com/docs/file1')
  const file2 = $rdf.sym('https://alice.example.com/docs/stuff/file2')
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
  const containerAclText = prefixes + ` <#auth> a acl:Authorization;
      acl:mode acl:Read;
      acl:agentClass foaf:Agent;
      acl:default <${container.uri}> .
`
  $rdf.parse(containerAclText, store, containerAcl.uri, 'text/turtle')
  console.log('@@' + containerAclText + '@@@')
  result = aclLogic.checkAccess(store, file1, container, containerAcl, alice, [ACL('Read')])
  t.ok(result, 'Alice should have Read access inherited - Public')

  result = aclLogic.checkAccess(store, file2, container, containerAcl, alice, [ACL('Read')])
  t.ok(result, 'Alice should have Read access inherited 2  - Public')

  result = !aclLogic.checkAccess(store, file2, container, containerAcl, alice, [ACL('Write')])
  t.ok(result, 'Alice should NOT have write access inherited  - Public')

  t.end()
})

/// /////////////////////////  Non-anonymoud versions
// Append access implied by Write acecss -PUBLIC
test('aclCheck checkAccess() test - Append access implied by Public Write acecss', t => {
  const resource = $rdf.sym('https://alice.example.com/docs/file1')
  const aclUrl = 'https://alice.example.com/docs/.acl'
  const aclDoc = $rdf.sym(aclUrl)

  const store = $rdf.graph() // Quad store
  const ACLtext = prefixes +
  ` <#auth> a acl:Authorization;
    acl:mode acl:Write;
    acl:agentClass acl:AuthenticatedAgent;
    acl:accessTo <${resource.uri}> .
  `
  $rdf.parse(ACLtext, store, aclUrl, 'text/turtle')

  const modesRequired = [ACL('Append')]

  const result = aclLogic.checkAccess(store, resource, null, aclDoc, alice, modesRequired)
  t.ok(result, 'Alice should have Append access implied by Write access - AuthenticatedAgent')

  t.end()
})

// Straight ACL access test
test('acl-check checkAccess() test - accessTo', function (t) {
  const container = $rdf.sym('https://alice.example.com/docs/')
  const containerAclUrl = 'https://alice.example.com/docs/.acl'
  const containerAcl = $rdf.sym(containerAclUrl)

  const store = $rdf.graph() // Quad store
  const ACLtext = prefixes +
  ` <#auth> a acl:Authorization;
    acl:mode acl:Read, acl:Write;
    acl:agentClass acl:AuthenticatedAgent;
    acl:accessTo <${container.uri}> .
  `
  $rdf.parse(ACLtext, store, containerAclUrl, 'text/turtle')

  var result = aclLogic.checkAccess(store, container, null, containerAcl, alice, [ACL('Read')])
  t.ok(result, 'Alice should have Read access - AuthenticatedAgent')

  result = aclLogic.checkAccess(store, container, null, containerAcl, alice, [ACL('Write')])
  t.ok(result, 'Alice should have Write acces')

  var result = !aclLogic.checkAccess(store, container, null, containerAcl, null, [ACL('Read')])
  t.ok(result, 'Anonymous should NOT have Read access to public thing - AuthenticatedAgent')

  result = !aclLogic.checkAccess(store, container, null, containerAcl, null, [ACL('Write')])
  t.ok(result, 'Anonymous should NOT have Write access - AuthenticatedAgent')

  result = aclLogic.checkAccess(store, container, null, containerAcl, bob, [ACL('Write')])
  t.ok(result, 'Bob should have Write access to public write - AuthenticatedAgent')

  t.end()
})

// Inheriting permissions from directory defaults
test('acl-check checkAccess() test - default/inherited', function (t) {
  const container = $rdf.sym('https://alice.example.com/docs/')
  const containerAcl = $rdf.sym('https://alice.example.com/docs/.acl')
  const file1 = $rdf.sym('https://alice.example.com/docs/file1')
  const file2 = $rdf.sym('https://alice.example.com/docs/stuff/file2')
  var result
  const store = $rdf.graph()
  const ACLtext = prefixes + ` <#auth> a acl:Authorization;
    acl:mode acl:Read;
    acl:agent bob:me;
    acl:accessTo <${file1.uri}> .
`
  $rdf.parse(ACLtext, store, containerAcl.uri, 'text/turtle')

  const containerAclText = prefixes + ` <#auth> a acl:Authorization;
      acl:mode acl:Read;
      acl:agentClass acl:AuthenticatedAgent;
      acl:default <${container.uri}> .
`
  $rdf.parse(containerAclText, store, containerAcl.uri, 'text/turtle')

  result = aclLogic.checkAccess(store, file1, container, containerAcl, alice, [ACL('Read')])
  t.ok(result, 'Alice should have Read access inherited - AuthenticatedAgent')

  result = aclLogic.checkAccess(store, file2, container, containerAcl, alice, [ACL('Read')])
  t.ok(result, 'Alice should have Read access inherited 2  - AuthenticatedAgent')

  result = !aclLogic.checkAccess(store, file2, container, containerAcl, alice, [ACL('Write')])
  t.ok(result, 'Alice should NOT have write access inherited  - AuthenticatedAgent')

  t.end()
})

test('aclCheck checkAccess() test - with use of originTrustedModes', t => {
  const resource = ALICE('docs/file1')
  const aclDoc = ALICE('docs/.acl')
  const aclUrl = aclDoc.uri

  const origin = $rdf.sym('https://apps.example.com')
  const aclStore = $rdf.graph()
  // grants read, write and control access to Alice
  const ACLtext = `${prefixes}
  <#auth> a acl:Authorization;
    acl:mode acl:Read, acl:Write, acl:Control;
    acl:agent alice:me;
    acl:accessTo ${resource} .
  `
  $rdf.parse(ACLtext, aclStore, aclUrl, 'text/turtle')

  const agent = alice
  const directory = null
  const trustedOrigins = []
  const originTrustedModes = [ACL('Read'), ACL('Write')]

  const readWriteModeRequired = [ACL('Read'), ACL('Write')]
  const readWriteModeResult = aclLogic.checkAccess(aclStore, resource, directory, aclDoc, agent, readWriteModeRequired, origin, trustedOrigins, originTrustedModes)
  t.ok(readWriteModeResult, 'Should get access to modes when origin is listed as trusted app')

  const controlModeRequired = [ACL('Control')]
  const controlModeResult = aclLogic.checkAccess(aclStore, resource, directory, aclDoc, agent, controlModeRequired, origin, trustedOrigins, originTrustedModes)
  t.ok(!controlModeResult, 'All Required Access Modes Not Granted', 'Correct reason')

  t.end()
})
