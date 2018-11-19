package org.nuxeo.customsecuritypolicy;

import org.nuxeo.ecm.core.api.NuxeoPrincipal;
import org.nuxeo.ecm.core.api.security.ACP;
import org.nuxeo.ecm.core.api.security.Access;
import org.nuxeo.ecm.core.model.Document;
import org.nuxeo.ecm.core.query.sql.NXQL;
import org.nuxeo.ecm.core.query.sql.model.*;
import org.nuxeo.ecm.core.query.sql.model.SQLQuery.Transformer;
import org.nuxeo.ecm.core.security.AbstractSecurityPolicy;
import org.nuxeo.ecm.core.security.SecurityPolicy;

import java.security.Principal;
import java.util.Optional;

/**
 * Sample policy for University.
 */
public class UniversityPolicy extends AbstractSecurityPolicy implements SecurityPolicy {

    @Override
    public Access checkPermission(Document doc, ACP mergedAcp, Principal principal, String permission,
                                  String[] resolvedPermissions, String[] additionalPrincipals) {
        NuxeoPrincipal nxPrinc = (NuxeoPrincipal) principal;

        if ("Invoice".equals(doc.getType().getName())) {
            Boolean isConfidential = Optional.ofNullable((Boolean) doc.getValue("university:confidential"))
                    .orElse(Boolean.FALSE);

            if (isConfidential && !nxPrinc.isMemberOf("university")) {
                return Access.DENY;
            }
        }
        return Access.UNKNOWN;
    }

    @Override
    public boolean isRestrictingPermission(String permission) {
        // could only restrict Browse permission, or others
        return true;
    }

    @Override
    public boolean isExpressibleInQuery(String repositoryName) {
        return true;
    }

    @Override
    public SQLQuery.Transformer getQueryTransformer(String repositoryName) {
        return IS_CONFIDENTIAL_TRANSFORMER;
    }

    public static final Transformer IS_CONFIDENTIAL_TRANSFORMER = new IsConfidentialTransformer();

    /**
     * Sample Transformer that adds {@code (ecm:primaryType = 'Invoice' AND university:confidential = true) OR ...} to
     * the query.
     */
    public static class IsConfidentialTransformer implements SQLQuery.Transformer {

        /**
         * {@code university:confidential = true}
         */
        public static final Predicate IS_CONFIDENTIAL = new Predicate(new Reference("university:confidential"),
                Operator.EQ, new IntegerLiteral(1L));
        /**
         * {@code ecm:primaryType = 'Invoice'}
         */
        public static final Predicate IS_INVOICE = new Predicate(new Reference(NXQL.ECM_PRIMARYTYPE),
                Operator.EQ, new StringLiteral("Invoice"));

        /**
         * {@code ecm:primaryType <> 'Invoice'}
         */
        public static final Predicate IS_NOT_INVOICE = new Predicate(new Reference(NXQL.ECM_PRIMARYTYPE),
                Operator.NOTEQ, new StringLiteral("Invoice"));

        public static final Predicate INVOICE_AND_CONFIDENTIAL = new Predicate(IS_CONFIDENTIAL, Operator.AND, IS_INVOICE);

        @Override
        public SQLQuery transform(Principal principal, SQLQuery query) {
            NuxeoPrincipal nxPrinc = (NuxeoPrincipal) principal;

            WhereClause where = query.where;
            Predicate predicate;
            Predicate predicate1;
            Predicate predicate2;
            if (!nxPrinc.isMemberOf("university")) {
                if (where == null || where.predicate == null) {
                    predicate1 = INVOICE_AND_CONFIDENTIAL;
                    predicate2 = IS_NOT_INVOICE;
                } else {
                    // adds an ecm:primaryType = 'Invoice' AND university:confidential = true to the WHERE clause
                    predicate1 = new Predicate(INVOICE_AND_CONFIDENTIAL, Operator.AND, where.predicate);
                    predicate2 = new Predicate(IS_NOT_INVOICE, Operator.AND, where.predicate);

                }
                predicate = new Predicate(predicate1, Operator.OR, predicate2);
                // return query with updated WHERE clause
                return new SQLQuery(query.select, query.from, new WhereClause(predicate), query.groupBy, query.having,
                        query.orderBy, query.limit, query.offset);
            }
            return query;

        }
    }
}
