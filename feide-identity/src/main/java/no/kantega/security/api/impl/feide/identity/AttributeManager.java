/*
 * Copyright (c) 2007 UNINETT FAS
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

package no.kantega.security.api.impl.feide.identity;

import java.io.UnsupportedEncodingException;
import java.util.StringTokenizer;
import java.util.Vector;

import com.iplanet.services.util.Base64;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;

/**
 * A very simple utility method to handle attributes received in
 * <code>SunTestServlet</code>.
 * @author Cato Olsen
 */
public class AttributeManager {

	private static org.apache.log4j.Logger log =
		org.apache.log4j.Logger.getLogger(AttributeManager.class);

    /**
     * Used for debug logging. Will write to the debug log
     * <code>feideClientUtilities</code>.
     */
    //private static Debug debug = Debug.getInstance("feideClientUtilities");

    /**
     * The name of the meta attribute used to hold the multi-value separator.
     */
    private final static String SEPARATOR_ATTRIBUTE_NAME = "no.feide.multivalue-separator";

    /**
     * The default multi-value separator, used whenever
     * <code>VALUE_SEPARATOR_ATTRIBUTE</code> could not be found in the SSO
     * token, or is an empty <code>String</code>. Should not normally occur.
     */
    private final static String SEPARATOR_ATTRIBUTE_DEFAULT = "_";

    /**
     * The character encoding used when Base64 decoding attribute values.
     */
    private final static String ATTRIBUTE_VALUE_ENCODING = "UTF-8";

    /**
     * The name of the meta attribute used to hold the list of available
     * attributes.
     */
    private final static String AVAILABLE_ATTRIBUTES_ATTRIBUTE = "no.feide.available-attributes";


    /**
     * Get the list of available attributes in an SSO token.
     * @param token
     *            The SSO token. Cannot be <code>null</code>.
     * @return The list of available attributes in the SSO token, or
     *         <code>null</code> if the attribute given by
     *         <code>AVAILABLE_ATTRIBUTES_ATTRIBUTE</code> does not exist.
     * @throws SSOException
     *             If unable to get the attribute given by
     *             <code>AVAILABLE_ATTRIBUTES_ATTRIBUTE</code> from the SSO
     *             token.
     * @see #AVAILABLE_ATTRIBUTES_ATTRIBUTE
     */
    public static String[] getAvailableAttributes(final SSOToken token)
    throws SSOException {

        // Sanity checks.
        if (token == null)
            throw new IllegalArgumentException("SSO token cannot be null");

        // Look up the attribute.
        final String values = token.getProperty(AVAILABLE_ATTRIBUTES_ATTRIBUTE);
        if ((values == null) || values.equals("")) {
            log.error("The attribute " + AVAILABLE_ATTRIBUTES_ATTRIBUTE + " does not exist in the SSO token");
            return new String[] {};
        }

        // Return the values as an array.
        // TODO: Should use the SEPARATOR_ATTRIBUTE_NAME here as well.
        log.debug("Available attributes are " + values);
        return split(values, ",");

    }


    /**
     * Return the raw (Base64 encoded) values of a given attribute from an SSO
     * token.
     * @param token
     *            The SSO token. Cannot be <code>null</code>.
     * @param name
     *            The attribute name. Must be non-empty.
     * @return The raw, Base64 encoded values of the given attribute, or
     *         <code>null</code> if the attribute <code>name</code> does not
     *         exist.
     * @throws SSOException
     *             If unable to get the attribute from the SSO token.
     */
    public static String[] getRawValues(final SSOToken token, final String name)
    throws SSOException {

        // Sanity checks.
        if (token == null)
            throw new IllegalArgumentException("SSO token cannot be null");
        if ((name == null) || name.equals(""))
            throw new IllegalArgumentException("Attribute name must be non-empty");

        // Look up the attribute and the separator.
        final String values = token.getProperty(name);
        if ((values == null) || values.equals("")) {
            log.debug("The attribute " + name + " does not exist in the SSO token");
            return new String[] {};
        }
        String separator = token.getProperty(SEPARATOR_ATTRIBUTE_NAME);
        if ((separator == null) || separator.equals("")) {
            log.warn("Separator meta attribute " + SEPARATOR_ATTRIBUTE_NAME + " not found in SSO token; using default separator " + SEPARATOR_ATTRIBUTE_DEFAULT);
            separator = SEPARATOR_ATTRIBUTE_DEFAULT;
        }

        // TODO: Workaround...
        separator = SEPARATOR_ATTRIBUTE_DEFAULT;

        // Return the values as an array.
        return split(values, separator);

    }


    /**
     * Return the Base64 decoded values of a given attribute from an SSO token.
     * @param token
     *            The SSO token. Cannot be <code>null</code>.
     * @param name
     *            The attribute name. Must be non-empty.
     * @return The Base64 decoded values of the given attribute, or
     *         <code>null</code> if the attribute <code>name</code> does not
     *         exist.
     * @throws SSOException
     *             If unable to get the attribute from the SSO token.
     * @throws UnsupportedEncodingException
     *             If unable to use the character encoding given by
     *             <code>VALUE_ENCODING</code>.
     * @see #ATTRIBUTE_VALUE_ENCODING
     */
    public static String[] getDecodedValues(final SSOToken token, final String name)
    throws SSOException, UnsupportedEncodingException {
    	log.debug("getDecodedValues enter name=" + name);

        // Get raw values.
        final String[] rawValues = getRawValues(token, name);

        // Base64 decode all values.
        Vector decoded = new Vector();
        for (int i = 0; i < rawValues.length; i++) {
            final byte[] buffer = Base64.decode(rawValues[i]);
            if ((buffer == null) || (buffer.length == 0)) {
                log.error("Unable to Base64 decode attribute " + name + " with raw value " + rawValues[i] + "; using raw value");
                decoded.add(rawValues[i]);
            } else
                decoded.add(new String(buffer, ATTRIBUTE_VALUE_ENCODING));
        }

        // Return the decoded values.
        return (String[])decoded.toArray(new String[] {});

    }


    /**
     * Utility method to split a multi-valued attribute into an array.
     * @param values
     *            The concatenated values.
     * @param separator
     *            The separator between values.
     * @return The <code>values</code> as an array.
     */
    private static String[] split(final String values, final String separator) {

        // Split the values into an array.
        StringTokenizer tokenizer = new StringTokenizer(values, separator);
        Vector converted = new Vector();
        while (tokenizer.hasMoreTokens())
            converted.add(tokenizer.nextToken());
        return (String[])converted.toArray(new String[] {});

    }

}