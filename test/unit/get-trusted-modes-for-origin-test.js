'use strict'

const test = require('tape')
const aclLogic = require('../../src/acl-check')
const $rdf = require('rdflib')

const ACL = $rdf.Namespace('http://www.w3.org/ns/auth/acl#')
const ALICE = $rdf.Namespace('https://alice.example.com/')
const alice = ALICE('#me')

const prefixes = `
@prefix acl: ${ACL()} .
@prefix alice: ${ALICE('#')} .
`

test('aclCheck getTrustedModesForOirign() test', t => {
  const origin = $rdf.sym('https://apps.example.com')
  const agent = alice
  const agentStore = $rdf.graph()
  const agentText = `${prefixes}
  ${agent} acl:trustedApp [  acl:origin ${origin};
                             acl:mode acl:Read, acl:Write].
  `
  $rdf.parse(agentText, agentStore, agent.uri, 'text/turtle')

  aclLogic.getTrustedModesForOrigin(agentStore, agent, origin).then(result => {
    t.deepEqual(result, [ACL('Read'), ACL('Write')], 'Should get a list of modes')
    t.end()
  })
})
