'use strict'

const test = require('tape')
const Authorization = require('../../src/authorization')
const { acl } = require('../../src/modes')
const PermissionSet = require('../../src/permission-set')
const aliceWebId = 'https://alice.example.com/#me'

test('PermissionSet checkAccess() test - Append access', t => {
  let resourceUrl = 'https://alice.example.com/docs/file1'
  let aclUrl = 'https://alice.example.com/docs/.acl'
  let ps = new PermissionSet(resourceUrl, aclUrl)
  ps.addPermission(aliceWebId, acl.WRITE)
  ps.checkAccess(resourceUrl, aliceWebId, acl.APPEND)
    .then(result => {
      t.ok(result, 'Alice should have Append access implied by Write access')
    })
    .catch(err => {
      t.fail(err)
    })
  t.end()
})

test('PermissionSet checkAccess() test - accessTo', function (t) {
  let containerUrl = 'https://alice.example.com/docs/'
  let containerAclUrl = 'https://alice.example.com/docs/.acl'
  let ps = new PermissionSet(containerUrl, containerAclUrl)
  ps.addPermission(aliceWebId, [acl.READ, acl.WRITE])

  ps.checkAccess(containerUrl, aliceWebId, acl.WRITE)
    .then(result => {
      t.ok(result, 'Alice should have write access to container')
    })
    .catch(err => {
      console.log(err)
      t.fail(err)
    })
  ps.checkAccess(containerUrl, 'https://someone.else.com/', acl.WRITE)
    .then(result => {
      t.notOk(result, 'Another user should have no write access')
    })
    .catch(err => {
      console.log(err)
      t.fail(err)
    })
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
