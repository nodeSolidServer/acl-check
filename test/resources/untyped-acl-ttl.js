module.exports = `@prefix acl: <http://www.w3.org/ns/auth/acl#>.
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#authorization>
    # Not present: a acl:Authorization;

    acl:agent 
        <https://alice.example.com/#me>;
    acl:accessTo <https://alice.example.com/docs/file1>;
    acl:mode
        acl:Read, acl:Write, acl:Control.`
