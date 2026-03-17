# LDAP Seed Files

Run these once after `docker compose up -d ldap_target`:

```bash
# 1. Add test users
ldapadd -x -D "cn=admin,dc=neutron,dc=local" -w adminpass \
        -H ldap://localhost:1389 -f ldap_seed/users.ldif

# 2. Enable anonymous read (fix default ACL)
docker exec autopwn_ldap bash -c '
cp /dev/stdin /tmp/fix_acl.ldif && ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/fix_acl.ldif
' < ldap_seed/fix_acl.ldif

# 3. Verify
ldapsearch -x -H ldap://localhost:1389 \
  -b "dc=neutron,dc=local" "(objectClass=inetOrgPerson)" uid cn
```
