'use strict'
const test = require('tape')
const acls = require('../../src/index')

test('Module exports test', t => {
  t.ok(acls.ALL_MODES)
  t.ok(acls.READ && acls.WRITE && acls.APPEND && acls.CONTROL)
  t.ok(acls.EVERYONE)
  t.ok(acls.INHERIT)
  t.ok(acls.ACCESS_TO)
  t.ok(acls.DEFAULT)
  t.ok(acls.getPermissions)
  t.ok(acls.clearPermissions)
  t.ok(acls.PermissionSet)
  t.ok(acls.Authorization)
  t.end()
})
