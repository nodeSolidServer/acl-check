'use strict'

const test = require('tape')
const before = test
const sinon = require('sinon')
const rdf = require('rdflib')
const Authorization = require('../../src/authorization')
const { acl } = require('../../src/modes')
const PermissionSet = require('../../src/permission-set')

const resourceUrl = 'https://alice.example.com/docs/file1'
const aclUrl = 'https://alice.example.com/docs/file1.acl'
const containerUrl = 'https://alice.example.com/docs/'
const containerAclUrl = 'https://alice.example.com/docs/.acl'
const bobWebId = 'https://bob.example.com/#me'
const aliceWebId = 'https://alice.example.com/#me'
// Not really sure what group webIDs will look like, not yet implemented:
const groupWebId = 'https://devteam.example.com/something'

function parseGraph (rdf, baseUrl, rdfSource, contentType = 'text/turtle') {
  const graph = rdf.graph()
  return new Promise((resolve, reject) => {
    rdf.parse(rdfSource, graph, baseUrl, contentType, (err, result) => {
      if (err) { return reject(err) }
      if (!result) {
        return reject(new Error('Error serializing the graph to ' +
          contentType))
      }
      resolve(result)
    })
  })
}
const rawAclSource = require('../resources/acl-container-ttl')
var parsedAclGraph

before('init graph', t => {
  return parseGraph(rdf, aclUrl, rawAclSource)
    .then(graph => {
      parsedAclGraph = graph
      t.end()
    })
    .catch(err => {
      t.fail(err)
    })
})

test('a new PermissionSet()', function (t) {
  const ps = new PermissionSet()
  t.ok(ps.isEmpty(), 'should be empty')
  t.equal(ps.count, 0, 'should have a count of 0')
  t.notOk(ps.resourceUrl, 'should have a null resource url')
  t.notOk(ps.aclUrl, 'should have a null acl url')
  t.end()
})

test('a new PermissionSet() for a resource', function (t) {
  const ps = new PermissionSet(resourceUrl)
  t.ok(ps.isEmpty(), 'should be empty')
  t.equal(ps.count, 0, 'should have a count of 0')
  t.equal(ps.resourceUrl, resourceUrl)
  t.notOk(ps.aclUrl, 'An acl url should be set explicitly')
  t.equal(ps.resourceType, PermissionSet.RESOURCE,
    'A permission set should be for a resource by default (not container)')
  t.end()
})

test('PermissionSet can add and remove agent authorizations', function (t) {
  const ps = new PermissionSet(resourceUrl, aclUrl)
  t.equal(ps.aclUrl, aclUrl)
  const origin = 'https://example.com/'
  // Notice that addPermission() is chainable:
  ps
    .addPermission(bobWebId, acl.READ, origin) // only allow read from origin
    .addPermission(aliceWebId, [acl.READ, acl.WRITE])
  t.notOk(ps.isEmpty())
  t.equal(ps.count, 2)
  let auth = ps.permissionFor(bobWebId)
  t.equal(auth.agent, bobWebId)
  t.equal(auth.resourceUrl, resourceUrl)
  t.equal(auth.resourceType, Authorization.RESOURCE)
  t.ok(auth.allowsOrigin(origin))
  t.ok(auth.allowsRead())
  t.notOk(auth.allowsWrite())
  // adding further permissions for an existing agent just merges access modes
  ps.addPermission(bobWebId, acl.WRITE)
  // should still only be 2 authorizations
  t.equal(ps.count, 2)
  auth = ps.permissionFor(bobWebId)
  t.ok(auth.allowsWrite())

  // Now remove the added permission
  ps.removePermission(bobWebId, acl.READ)
  // Still 2 authorizations, agent1 has a WRITE permission remaining
  t.equal(ps.count, 2)
  auth = ps.permissionFor(bobWebId)
  t.notOk(auth.allowsRead())
  t.ok(auth.allowsWrite())

  // Now, if you remove the remaining WRITE permission from agent1, that whole
  // authorization is removed
  ps.removePermission(bobWebId, acl.WRITE)
  t.equal(ps.count, 1, 'Only one authorization should remain')
  t.notOk(ps.permissionFor(bobWebId),
    'No authorization for agent1 should be found')
  t.end()
})

test('PermissionSet no duplicate authorizations test', function (t) {
  const ps = new PermissionSet(resourceUrl, aclUrl)
  // Now add two identical permissions
  ps.addPermission(aliceWebId, [acl.READ, acl.WRITE])
  ps.addPermission(aliceWebId, [acl.READ, acl.WRITE])
  t.equal(ps.count, 1, 'Duplicate authorizations should be eliminated')
  t.end()
})

test('PermissionSet can add and remove group authorizations', function (t) {
  const ps = new PermissionSet(resourceUrl)
  // Let's add an agentGroup permission
  ps.addGroupPermission(groupWebId, [acl.READ, acl.WRITE])
  t.equal(ps.count, 1)
  const auth = ps.permissionFor(groupWebId)
  t.equal(auth.group, groupWebId)
  ps.removePermission(groupWebId, [acl.READ, acl.WRITE])
  t.ok(ps.isEmpty())
  t.end()
})

test('iterating over a PermissionSet', function (t) {
  const ps = new PermissionSet(resourceUrl, aclUrl)
  ps
    .addPermission(bobWebId, acl.READ)
    .addPermission(aliceWebId, [acl.READ, acl.WRITE])
  ps.forEach(function (auth) {
    t.ok(auth.hashFragment() in ps.authorizations)
  })
  t.end()
})

test.skip('a PermissionSet() for a container', function (t) {
  const isContainer = true
  const ps = new PermissionSet(containerUrl, aclUrl, isContainer)
  t.ok(ps.isAuthInherited(),
    'A PermissionSet for a container should be inherited by default')
  ps.addPermission(bobWebId, acl.READ)
  const auth = ps.permissionFor(bobWebId)
  t.ok(auth.isInherited(),
    'An authorization intended for a container should be inherited by default')
  t.end()
})

test('a PermissionSet() for a resource (not container)', function (t) {
  const ps = new PermissionSet(containerUrl)
  t.notOk(ps.isAuthInherited())
  ps.addPermission(bobWebId, acl.READ)
  const auth = ps.permissionFor(bobWebId)
  t.notOk(auth.isInherited(),
    'An authorization intended for a resource should not be inherited by default')
  t.end()
})

test('a PermissionSet can be initialized from an .acl graph', function (t) {
  const isContainer = false
  // see test/resources/acl-container-ttl.js
  const ps = new PermissionSet(resourceUrl, aclUrl, isContainer,
    { graph: parsedAclGraph, rdf })

  // Check to make sure Alice's authorizations were read in correctly
  const auth = ps.findAuthByAgent(aliceWebId, resourceUrl)
  t.ok(auth, 'Alice should have a permission for /docs/file1')
  t.ok(auth.isInherited())
  t.ok(auth.allowsWrite() && auth.allowsWrite() && auth.allowsControl())
  // Check to make sure the acl:origin objects were read in
  t.ok(auth.allowsOrigin('https://example.com/'))
  // Check to make sure the `mailto:` agent objects were read in
  // This is @private / unofficial functionality, used only in the root ACL
  t.ok(auth.mailTo.length > 0, 'Alice agent should have a mailto: set')
  t.equal(auth.mailTo[0], 'alice@example.com')
  t.equal(auth.mailTo[1], 'bob@example.com')
  // Check to make sure Bob's authorizations were read in correctly
  const auth2 = ps.findAuthByAgent(bobWebId, resourceUrl)
  t.ok(auth2, 'Container acl should also have an authorization for Bob')
  t.ok(auth2.isInherited())
  t.ok(auth2.allowsWrite() && auth2.allowsWrite() && auth2.allowsControl())
  t.ok(auth2.mailTo.length > 0, 'Bob agent should have a mailto: set')
  t.equal(auth2.mailTo[0], 'alice@example.com')
  t.equal(auth2.mailTo[1], 'bob@example.com')
  // // Now check that the Public Read authorization was parsed
  const publicResource = 'https://alice.example.com/profile/card'
  const publicAuth = ps.findPublicAuth(publicResource)
  t.ok(publicAuth.isPublic())
  t.notOk(publicAuth.isInherited())
  t.ok(publicAuth.allowsRead())
  t.end()
})

test('PermissionSet equals test 1', function (t) {
  const ps1 = new PermissionSet()
  const ps2 = new PermissionSet()
  t.ok(ps1.equals(ps2))
  t.end()
})

test('PermissionSet equals test 2', function (t) {
  const ps1 = new PermissionSet(resourceUrl)
  const ps2 = new PermissionSet()
  t.notOk(ps1.equals(ps2))
  ps2.resourceUrl = resourceUrl
  t.ok(ps1.equals(ps2))

  ps1.aclUrl = aclUrl
  t.notOk(ps1.equals(ps2))
  ps2.aclUrl = aclUrl
  t.ok(ps1.equals(ps2))
  t.end()
})

test('PermissionSet equals test 3', function (t) {
  const ps1 = new PermissionSet(containerUrl, containerAclUrl,
    PermissionSet.CONTAINER)
  const ps2 = new PermissionSet(containerUrl, containerAclUrl)
  t.notOk(ps1.equals(ps2))
  ps2.resourceType = PermissionSet.CONTAINER
  t.ok(ps1.equals(ps2))
  t.end()
})

test('PermissionSet equals test 4', function (t) {
  const ps1 = new PermissionSet(resourceUrl)
  ps1.addPermission(aliceWebId, acl.READ)
  const ps2 = new PermissionSet(resourceUrl)
  t.notOk(ps1.equals(ps2))
  ps2.addPermission(aliceWebId, acl.READ)
  t.ok(ps1.equals(ps2))
  t.end()
})

test('PermissionSet serialized & deserialized round trip test', function (t) {
  var ps = new PermissionSet(containerUrl, containerAclUrl,
    PermissionSet.CONTAINER, { graph: parsedAclGraph, rdf })
  const auth = ps.permissionFor(aliceWebId)
  // console.log(ps.serialize())
  t.ok(ps.equals(ps), 'A PermissionSet should equal itself')
  // Now check to make sure serialize() & reparse results in the same set
  return ps.serialize()
    .then((serializedTurtle) => {
      // Now that the PermissionSet is serialized to a Turtle string,
      // let's re-parse that string into a new graph
      return parseGraph(rdf, containerAclUrl, serializedTurtle)
    })
    .then(parsedGraph => {
      const ps2 = new PermissionSet(containerUrl, containerAclUrl,
        PermissionSet.CONTAINER, { graph: parsedGraph, rdf })
      // console.log(ps2.serialize())
      t.ok(ps.equals(ps2),
        'A PermissionSet serialized and re-parsed should equal the original one')
      t.end()
    })
})

test('PermissionSet allowsPublic() test', function (t) {
  var ps = new PermissionSet(containerUrl, containerAclUrl,
    PermissionSet.CONTAINER, { graph: parsedAclGraph, rdf })
  const otherUrl = 'https://alice.example.com/profile/card'
  t.ok(ps.allowsPublic(acl.READ, otherUrl),
    'Alice\'s profile should be public-readable')
  t.notOk(ps.allowsPublic(acl.WRITE, otherUrl),
    'Alice\'s profile should not be public-writable')
  t.end()
})

test('allowsPublic() should ignore origin checking', function (t) {
  const origin = 'https://example.com'
  const options = { graph: parsedAclGraph, rdf, origin, strictOrigin: true }
  var ps = new PermissionSet(containerUrl, containerAclUrl,
    PermissionSet.CONTAINER, options)
  const otherUrl = 'https://alice.example.com/profile/card'
  t.ok(ps.allowsPublic(acl.READ, otherUrl))

  ps.checkAccess(otherUrl, 'https://alice.example.com', acl.READ)
    .then(hasAccess => {
      t.ok(hasAccess)
      t.end()
    })
})

test('PermissionSet init from untyped ACL test', function (t) {
  const rawAclSource = require('../resources/untyped-acl-ttl')
  const resourceUrl = 'https://alice.example.com/docs/file1'
  const aclUrl = 'https://alice.example.com/docs/file1.acl'
  const isContainer = false
  parseGraph(rdf, aclUrl, rawAclSource)
    .then(graph => {
      const ps = new PermissionSet(resourceUrl, aclUrl, isContainer,
        { graph, rdf })
      t.ok(ps.count,
        'Permission set should init correctly without acl:Authorization type')
      t.end()
    })
})

test('PermissionSet serialize() no rdf test', t => {
  const ps = new PermissionSet()
  ps.serialize()
    .then(() => {
      t.fail('Serialize should not succeed with no rdf lib')
    })
    .catch(err => {
      t.equal(err.message, 'Cannot save - no rdf library')
      t.end()
    })
})

test('PermissionSet serialize() rdflib errors test', t => {
  const ps = new PermissionSet(resourceUrl, aclUrl, false,
    { rdf, graph: parsedAclGraph })
  ps.serialize({ contentType: 'invalid' })
    .then(() => {
      t.fail('Serialize should not succeed with an rdflib error')
    })
    .catch(err => {
      t.ok(err.message.startsWith('Serialize: Content-type invalid'))
      t.end()
    })
})

test('PermissionSet save() test', t => {
  const resourceUrl = 'https://alice.example.com/docs/file1'
  const aclUrl = 'https://alice.example.com/docs/file1.acl'
  const isContainer = false
  const putStub = sinon.stub().returns(Promise.resolve())
  const mockWebClient = {
    put: putStub
  }
  const ps = new PermissionSet(resourceUrl, aclUrl, isContainer,
    { rdf, graph: parsedAclGraph, webClient: mockWebClient })
  let serializedGraph
  ps.serialize()
    .then(ttl => {
      serializedGraph = ttl
      return ps.save()
    })
    .then(() => {
      t.ok(putStub.calledWith(aclUrl, serializedGraph, 'text/turtle'),
        'ps.save() should result to a PUT to .acl url')
      t.end()
    })
    .catch(err => {
      console.log(err)
      t.fail()
    })
})

test('PermissionSet save() no aclUrl test', t => {
  let nullAclUrl
  const ps = new PermissionSet(resourceUrl, nullAclUrl, false,
    { rdf, graph: parsedAclGraph })
  ps.save()
    .then(() => {
      t.fail('ps.save() should not succeed with no acl url set')
    })
    .catch(err => {
      t.equal(err.message, 'Cannot save - unknown target url')
      t.end()
    })
})

test('PermissionSet save() no web client test', t => {
  let nullAclUrl
  const ps = new PermissionSet(resourceUrl, aclUrl, false,
    { rdf, graph: parsedAclGraph })
  ps.save()
    .then(() => {
      t.fail('ps.save() should not succeed with no web client set')
    })
    .catch(err => {
      t.equal(err.message, 'Cannot save - no web client')
      t.end()
    })
})
