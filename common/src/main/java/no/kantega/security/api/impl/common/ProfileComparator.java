package no.kantega.security.api.impl.common;

import no.kantega.security.api.profile.Profile;

import java.util.Comparator;
import java.util.Locale;
import java.text.Collator;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jun 7, 2007
 * Time: 10:48:14 AM
 */
public class ProfileComparator implements Comparator {
    Collator collator = null;

    public ProfileComparator() {
        collator = Collator.getInstance(new Locale("no", "NO"));
        collator.setStrength(Collator.PRIMARY);
    }

    public int compare(Object o1, Object o2) {
        Profile p1 = (Profile)o1;
        Profile p2 = (Profile)o2;

        String s1 = p1.getGivenName() + " " + p1.getSurname();
        String s2 = p2.getGivenName() + " " + p2.getSurname();
        return collator.compare(s2, s1);
    }
}
