package edu.aem.training.usermgr;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Reference;
import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlList;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.sling.jcr.api.SlingRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.jackrabbit.api.security.user.UserManager;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.security.AccessControlList;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicyIterator;
import javax.jcr.security.Privilege;
import java.util.NoSuchElementException;

@Component
public class ModifyPermission {

    private static final String CONTENT_GEO_FR = "/content/geometrixx/fr";

    private static final Logger log = LoggerFactory.getLogger(ModifyPermission.class);

    @Reference
    private SlingRepository repo;

    @Activate
    protected void activate() {

        log.info("ModifyPermissions activated");
        modifyPermissions();
    }

    private void modifyPermissions() {

        Session session = null;

        try {
            session = repo.loginAdministrative(null);
            UserManager userMgr = ((JackrabbitSession)session).getUserManager();
            AccessControlManager accessControlManager = session.getAccessControlManager();
            Authorizable denyAccess = userMgr.getAuthorizable("deny-access");
            AccessControlPolicyIterator policyIterator = accessControlManager.getApplicablePolicies(CONTENT_GEO_FR);
            AccessControlList acl;

            try {
                acl = (JackrabbitAccessControlList) policyIterator.nextAccessControlPolicy();
            } catch(NoSuchElementException e) {
                acl = (JackrabbitAccessControlList) accessControlManager.getPolicies(CONTENT_GEO_FR)[0];
            }

            Privilege[] privileges = { accessControlManager.privilegeFromName(Privilege.JCR_READ) };
            acl.addAccessControlEntry(denyAccess.getPrincipal(), privileges);
            accessControlManager.setPolicy(CONTENT_GEO_FR, acl);
            session.save();

        } catch(RepositoryException e) {
            log.info("ERROR: " + e.getMessage());
        } finally {
            if(session != null) {
                session.logout();
            }
        }
    }
}
