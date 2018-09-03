// Access control logic

const $rdf = require('rdflib')

const ACL = $rdf.Namespace('http://www.w3.org/ns/auth/acl#')
const FOAF = $rdf.Namespace('http://xmlns.com/foaf/0.1/')
const VCARD = $rdf.Namespace('http://www.w3.org/2006/vcard/ns#')

module.exports = {}

function publisherTrustedApp (kb, doc, aclDoc, modesRequired, origin, docAuths) {
  let app = $rdf.sym(origin)
  let appAuths = docAuths.filter(auth => kb.holds(auth, ACL('mode'), ACL('Control'), aclDoc))
  let owners = appAuths.map(auth => kb.each(auth, ACL('agent'))).flat() //  owners
  let relevant = owners.map(owner => kb.each(owner, ACL('trust'), null, owner.doc()).filter(
    ta => kb.holds(ta, ACL('trustedApp'), app, owner.doc()))).flat() // ta's
  let modesOK = relevant.map(ta => kb.each(ta, ACL('mode'))).flat().map(m => m.uri)
  let modesRequiredURIs = modesRequired.map(m => m.uri)
  modesRequiredURIs.every(uri => modesOK.includes(uri))
  // modesRequired.every(mode => appAuths.some(auth => kb.holds(auth, ACL('mode'), mode, aclDoc)))
}

function aclCheck (kb, doc, directory, aclDoc, agent, modesRequired, origin, trustedOrigins) {
  var auths = kb.each(null, ACL('accessTo'), doc, aclDoc)
  if (directory) {
    auths = auths.concat(null, (ACL('defaultForNew'), directory)) // Deprecated but keep for ages
    auths = auths.concat(null, (ACL('default'), directory))
  }
  if (origin && trustedOrigins && trustedOrigins.includes(origin)) {
    console.log('Origin ' + origin + ' is trusted')
    origin = null // stop worrying about origin
  }
  function agentOrGroupOK (auth, agent) {
    if (kb.holds(auth, ACL('accessToClass'), FOAF('Agent'), aclDoc)) return true
    if (!agent) return false
    return kb.holds(auth, ACL('accessToClass'), ACL('AuthenticatedAgent'), aclDoc) ||
      kb.holds(auth, ACL('agent'), agent, aclDoc) ||
      kb.each(auth, ACL('accessToGroup'), null, aclDoc).some(group => kb.holds(agent, VCARD('member'), group, group.doc()))
  }
  function originOK (auth, origin) {
    return kb.holds(auth, ACL('origin'), origin, aclDoc)
  }
  return modesRequired.every(mode =>
    auths.filter(auth => kb.holds(auth, ACL('mode'), mode, aclDoc)).some(
      auth => (agentOrGroupOK(auth, agent)) && (!origin || originOK(auth, origin)))
  )
}

function aclCheck1 (kb, doc, directory, aclDoc, agent, modesRequired, origin, trustedOrigins) {
  var auths = kb.each(null, ACL('accessTo'), doc, aclDoc)
  if (directory) {
    auths = auths.concat(null, (ACL('defaultForNew'), doc)) // Deprecated but keep for ages
    auths = auths.concat(null, (ACL('default'), doc))
  }
  if (origin && trustedOrigins && trustedOrigins.includes(origin)) {
    console.log('Origin ' + origin + ' is trusted')
    origin = null // stop worrying about origin
  }
  function agentOrGroupOK (auth, agent) {
    if (kb.holds(auth, ACL('accessToClass'), FOAF('Agent'), aclDoc)) return true
    if (!agent) return false
    return kb.holds(auth, ACL('accessToClass'), ACL('AuthenticatedAgent'), aclDoc) ||
      kb.holds(auth, ACL('agent'), agent, aclDoc) ||
      kb.each(auth, ACL('accessToGroup'), null, aclDoc).some(group => kb.holds(agent, VCARD('member'), group, group.doc()))
  }
  function originOK (auth, origin) {
    return kb.holds(auth, ACL('origin'), origin, aclDoc)
  }
  return modesRequired.every(mode =>
    auths.filter(auth => kb.holds(auth, ACL('mode'), mode, aclDoc)).some(
      auth => (agentOrGroupOK(auth, agent)) && (!origin || originOK(auth, origin)))
  )
}

function aclCheck0 (kb, doc, directory, aclDoc, agent, modesRequired, origin, trustedOrigins) {
  var auths = kb.each(null, ACL('accessTo'), doc)
  if (directory) {
    auths = auths.concat(null, (ACL('defaultForNew'), doc)) // Deprecated but keep for ages
    auths = auths.concat(null, (ACL('default'), doc))
  }
  if (origin && trustedOrigins && trustedOrigins.includes(origin)) {
    console.log('Origin ' + origin + ' is trusted')
    origin = null // stop worrying about origin
  }
  return modesRequired.every(mode =>
     auths.some(auth =>
       kb.holds(auth, ACL('agent'), agent) && kb.holds(auth, ACL('mode'), mode)) &&
       (!origin ||
      auths.some(auth => kb.holds(auth, ACL('origin'), origin) && kb.holds(auth, ACL('mode'), mode))
    )
  )
}

module.exports.aclCheck = aclCheck
module.exports.aclCheck0 = aclCheck0
module.exports.aclCheck1 = aclCheck1
module.exports.publisherTrustedApp = publisherTrustedApp
