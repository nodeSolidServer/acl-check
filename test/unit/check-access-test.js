'use strict'

const test = require('tape')
// const Authorization = require('../../src/authorization')
// const { acl } = require('../../src/modes')
// const PermissionSet = require('../../src/permission-set')
const aclLogic = require('../../src/acl-check')
const $rdf = require('rdflib')

const ACL = $rdf.Namespace('http://www.w3.org/ns/auth/acl#')

const prefixes = `@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix alice: <https://alice.example.com/>.
`
const aliceWebId = 'https://alice.example.com/#me'
const alice = $rdf.sym('https://alice.example.com/#me')
const bob = $rdf.sym('https://bob.example.com/#me')

test('aclCheck checkAccess() test - Append access', t => {
  let resourceUrl = 'https://alice.example.com/docs/file1'
  let resource = $rdf.sym(resourceUrl)
  let aclUrl = 'https://alice.example.com/docs/.acl'
  let aclDoc = $rdf.sym(aclUrl)
  // let ps = new PermissionSet(resourceUrl, aclUrl)
  // ps.addPermission(aliceWebId, acl.WRITE)

  const kb = $rdf.graph() // Quad store
  const ACLtext = prefixes +
  ` <#> a acl:Authorization;
    acl:mode acl:Read;
    acl:agent alice:me;
    acl:accessTo <${resourceUrl}> .
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
  /*
  ps.checkAccess(resourceUrl, aliceWebId, acl.APPEND)
    .then(result => {
      t.ok(result, 'Alice should have Append access implied by Write access')
    })
    .catch(err => {
      t.fail(err)
    })
  */
  t.end()
})

test('PermissionSet checkAccess() test - accessTo', function (t) {
  let containerUrl = 'https://alice.example.com/docs/'
  let container = $rdf.sym(containerUrl)
  let containerAclUrl = 'https://alice.example.com/docs/.acl'
  let containerAcl = $rdf.sym(containerAclUrl)
  // let ps = new PermissionSet(containerUrl, containerAclUrl)
  // ps.addPermission(aliceWebId, [acl.READ, acl.WRITE])

  const kb = $rdf.graph() // Quad store
  const ACLtext = prefixes +
  ` <#> a acl:Authorization;
    acl:mode acl:Read, acl:Write;
    acl:agent alice:me;
    acl:accessTo <${containerUrl}> .
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

test('PermissionSet checkAccess() test - default/inherited', function (t) {
  let containerUrl = 'https://alice.example.com/docs/'
  let containerAclUrl = 'https://alice.example.com/docs/.acl'
  let ps = new PermissionSet(containerUrl, containerAclUrl)
  // Now add a default / inherited permission for the container
  let inherit = true
  ps.addAuthorizationFor(containerUrl, inherit, aliceWebId, acl.READ)

  let resourceUrl = 'https://alice.example.com/docs/file1'
  ps.checkAccess(resourceUrl, aliceWebId, acl.READ)
    .then(result => {
      t.ok(result, 'Alice should have inherited read access to file')
    })
    .catch(err => {
      console.log(err)
      t.fail(err)
    })
  let randomUser = 'https://someone.else.com/'
  ps.checkAccess(resourceUrl, randomUser, acl.READ)
    .then(result => {
      t.notOk(result, 'Another user should not have inherited access to file')
    })
    .catch(err => {
      console.log(err)
      t.fail(err)
    })
  t.end()
})

test('PermissionSet checkAccess() test - public access', function (t) {
  let containerUrl = 'https://alice.example.com/docs/'
  let containerAclUrl = 'https://alice.example.com/docs/.acl'
  let ps = new PermissionSet(containerUrl, containerAclUrl)
  let inherit = true

  // First, let's test an inherited allow public read permission
  let auth1 = new Authorization(containerUrl, inherit)
  auth1.setPublic()
  auth1.addMode(acl.READ)
  ps.addAuthorization(auth1)
  // See if this file has inherited access
  let resourceUrl = 'https://alice.example.com/docs/file1'
  let randomUser = 'https://someone.else.com/'
  ps.checkAccess(resourceUrl, randomUser, acl.READ)
    .then(result => {
      t.ok(result, 'Everyone should have inherited read access to file')
    })
    .catch(err => {
      console.log(err)
      t.fail(err)
    })
  // Reset the permission set, test a non-default permission
  ps = new PermissionSet()
  let auth2 = new Authorization(resourceUrl, !inherit)
  auth2.setPublic()
  auth2.addMode(acl.READ)
  ps.addAuthorization(auth2)
  ps.checkAccess(resourceUrl, randomUser, acl.READ)
    .then(result => {
      t.ok(result, 'Everyone should have non-inherited read access to file')
    })
    .catch(err => {
      console.log(err)
      t.fail(err)
    })

  t.end()
})
