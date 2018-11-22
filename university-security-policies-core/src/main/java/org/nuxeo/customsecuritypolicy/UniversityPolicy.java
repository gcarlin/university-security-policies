package org.nuxeo.customsecuritypolicy;

import org.nuxeo.ecm.core.api.NuxeoPrincipal;
import org.nuxeo.ecm.core.api.security.ACP;
import org.nuxeo.ecm.core.api.security.Access;
import org.nuxeo.ecm.core.model.Document;
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

    private static final String UNIVERSITY = "university";
    private static final String UNIVERSITY_CONFIDENTIAL = UNIVERSITY + ":confidential";

    private static final Transformer IS_CONFIDENTIAL_TRANSFORMER = new IsConfidentialTransformer();

    @Override
    public Access checkPermission(Document doc, ACP mergedAcp, Principal principal, String permission,
                                  String[] resolvedPermissions, String[] additionalPrincipals) {
        NuxeoPrincipal nxPrinc = (NuxeoPrincipal) principal;

        // Whenever this is an Invoice
        if ("Invoice".equals(doc.getType().getName())) {
            // Check the value of confidential, false or null are considered the same
            Boolean isConfidential = Optional.ofNullable((Boolean) doc.getValue(UNIVERSITY_CONFIDENTIAL))
                    .orElse(Boolean.FALSE);

            // If you are not part of the group university we check the confidential value.
            if (isConfidential && !nxPrinc.isMemberOf(UNIVERSITY)) {
                return Access.DENY;
            }
        }
        return Access.UNKNOWN;
    }

    @Override
    public boolean isRestrictingPermission(String permission) {
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

    /**
     * Sample Transformer that adds {@code (university:confidential IS NULL OR university:confidential = 0) AND ...} to
     * the query.
     */
    public static class IsConfidentialTransformer implements SQLQuery.Transformer {

        /**
         * {@code university:confidential = 0}
         */
        private static final Predicate IS_NOT_CONFIDENTIAL = new Predicate(new Reference(UNIVERSITY_CONFIDENTIAL),
                Operator.EQ, new IntegerLiteral(0l));

        /**
         * {@code university:confidential IS NULL}
         */
        private static final Predicate IS_NOT_CONFIDENTIAL_NULL = new Predicate(new Reference(UNIVERSITY_CONFIDENTIAL),
                Operator.ISNULL, null);

        /**
         * There's no default value on the confidential property so we have to check the null value.
         * {@code university:confidential IS NULL OR university:confidential = 0}
         */
        private static final Predicate INVOICE_AND_NOT_CONFIDENTIAL = new Predicate(IS_NOT_CONFIDENTIAL_NULL, Operator.OR, IS_NOT_CONFIDENTIAL);

        @Override
        public SQLQuery transform(Principal principal, SQLQuery query) {
            NuxeoPrincipal nxPrinc = (NuxeoPrincipal) principal;

            WhereClause where = query.where;
            Expression predicate;
            if (!nxPrinc.isMemberOf(UNIVERSITY) && !nxPrinc.isAdministrator()) {
                if (where == null || where.predicate == null) {
                    predicate = IS_NOT_CONFIDENTIAL;

                } else {
                    // Parenthesis are applied from the left to the right we will have something like:
                    // SELECT * FROM Document WHERE (((university:confidential IS NULL) OR (university:confidential = 0)) AND ... )
                    predicate = new Expression(INVOICE_AND_NOT_CONFIDENTIAL, Operator.AND, where.predicate);
                }
                // return query with updated WHERE clause
                return new SQLQuery(query.select, query.from, new WhereClause(predicate), query.groupBy, query.having,
                        query.orderBy, query.limit, query.offset);
            }
            return query;
        }
    }
}
