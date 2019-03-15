'use strict'

const test = require('tape')
const aclLogic = require('../../src/acl-check')
const $rdf = require('rdflib')

const ACL = $rdf.Namespace('http://www.w3.org/ns/auth/acl#')
const ALICE = $rdf.Namespace('https://alice.example.com/')
const alice = ALICE('#me')
const BOB = $rdf.Namespace('https://bob.example.com/')
const bob = BOB('#me')

const prefixes = `
@prefix acl: ${ACL()} .
@prefix alice: ${ALICE('#')} .
`

test('aclCheck getTrustedModesForOrigin() getting trusted modes from publisherStore (acl:accessTo on resource)', t => {
  const origin = $rdf.sym('https://apps.example.com')
  const doc = ALICE('some/doc.txt')
  const aclDoc = ALICE('some/doc.txt.acl')
  const publisher = alice
  const requester = bob
  const publisherStore = $rdf.graph()
  const aclFileText = `${prefixes}
<#owner>
    a acl:Authorization;
    acl:agent ${publisher};
    acl:accessTo ${doc};
    acl:mode acl:Control.
  `
  $rdf.parse(aclFileText, publisherStore, aclDoc.uri, 'text/turtle')
  const publisherText = `${prefixes}
  ${publisher} acl:trustedApp [  acl:origin ${origin};
                             acl:mode acl:Read, acl:Write].
  `
  $rdf.parse(publisherText, publisherStore, publisher.uri, 'text/turtle')

  aclLogic.getTrustedModesForOrigin(publisherStore, doc, null, aclDoc, origin, Promise.resolve.bind(Promise)).then(result => {
    t.deepEqual(result, [ACL('Read'), ACL('Write')], 'Should get a list of modes')
    t.end()
  })
})

test('aclCheck getTrustedModesForOrigin() getting trusted modes from publisherStore (acl:accessTo on container)', t => {
  const origin = $rdf.sym('https://apps.example.com')
  const container = ALICE('some/')
  const doc = ALICE('some/doc.txt')
  const aclDoc = ALICE('some/doc.txt.acl')
  const publisher = alice
  const requester = bob
  const publisherStore = $rdf.graph()
  const aclFileText = `${prefixes}
<#owner>
    a acl:Authorization;
    acl:agent ${publisher};
    acl:default ${container};
    acl:mode acl:Control.
  `
  $rdf.parse(aclFileText, publisherStore, aclDoc.uri, 'text/turtle')
  const publisherText = `${prefixes}
  ${publisher} acl:trustedApp [  acl:origin ${origin};
                             acl:mode acl:Read, acl:Write].
  `
  $rdf.parse(publisherText, publisherStore, publisher.uri, 'text/turtle')

  aclLogic.getTrustedModesForOrigin(publisherStore, doc, container, aclDoc, origin, Promise.resolve.bind(Promise)).then(result => {
    t.deepEqual(result, [ACL('Read'), ACL('Write')], 'Should get a list of modes')
    t.end()
  })
})
