package no.kantega.security.api.impl.common;

import no.kantega.security.api.profile.Profile;
import no.kantega.security.api.role.Role;

import java.util.Comparator;
import java.util.Locale;
import java.text.Collator;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jun 7, 2007
 * Time: 10:57:32 AM
 */
public class RoleComparator implements Comparator {
    Collator collator = null;

    public RoleComparator() {
        collator = Collator.getInstance(new Locale("no", "NO"));
        collator.setStrength(Collator.PRIMARY);
    }

    public int compare(Object o1, Object o2) {
        Role r1 = (Role)o1;
        Role r2 = (Role)o2;

        return collator.compare(r2.getName(), r1.getName());
    }
}
