# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Emmanuel Benoît (@tseeker) <tseeker@nocternity.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.errors import AnsibleError, AnsibleFilterError, AnsibleFilterTypeError
from io import BytesIO, StringIO
import functools
import re

try:
    import ldif
    import ldap
    HAS_LIB = True
except ImportError:
    HAS_LIB = False


def _try_utf8(inval):
    ''' Try to convert a bunch of bytes into an UTF-8 string.

    Args:
        inval (bytes): raw data received from the LDAP server

    Returns:
        An UTF-8 string decoded from the input, or the raw input if decoding
        failed.
    '''
    try:
        return inval.decode("utf-8")
    except ValueError:
        return inval


_WEIGHTED_ATTR = re.compile(r"^\{(-?\d+)\}(.+)$")
''' RE that identifies and extracts weighted attribute value components. '''


def _check_lib():
    ''' Ensure that the python-ldap library is present.

    Throws:
        AnsibleError: the python-ldap library could not be found
    '''
    if not HAS_LIB:
        raise AnsibleError("The python-ldap library must be installed in order to use this plugin.")


def _dn_compare(rec1, rec2, mix_weighted):
    ''' Comparison function for configuration records' DNs

    This function is used to compare DNs to one another when sorting LDIF entries.

    Args:
        rec1 (dict): the first record
        rec2 (dict): the second record
        mix_weighted (bool): whether comparing weighted to unweighted RDNs will be tolerated

    Returns:
        -1 if rec1.dn < rec2.dn, 0 if rec1.dn == rec2.dn or 1 if rec1.dn > rec2.dn

    Throws:
        AnsibleFilterError: if a multi-valued RDN is found or if unweighted and weighted
                            values are being compared.
    '''
    dn1 = rec1["dn"]
    dn2 = rec2["dn"]
    if dn1 == dn2:
        return 0

    def _next_rdn(rdns):
        ''' Fetch and remove the next RDN from a split DN. '''
        return (ldap.dn.str2dn(rdns.pop()))[0]

    def _rdn_av(rdn):
        ''' Split a RDN into an attribute name and a value. '''
        return (rdn[0][0].lower(), rdn[0][1])

    dn1_rdns = ldap.dn.explode_dn(dn1)
    dn2_rdns = ldap.dn.explode_dn(dn2)
    while len(dn1_rdns) > 0 and len(dn2_rdns) > 0:
        dn1_rdn = _next_rdn(dn1_rdns)
        dn2_rdn = _next_rdn(dn2_rdns)
        if len(dn1_rdn) != 1 or len(dn2_rdn) != 1:
            raise AnsibleFilterError("Multi-valued RDNs are not supported")
        (dn1_attr, dn1_val) = _rdn_av(dn1_rdn)
        (dn2_attr, dn2_val) = _rdn_av(dn2_rdn)
        # Compare attribute names
        if dn1_attr < dn2_attr:
            return -1
        elif dn1_attr > dn2_attr:
            return 1
        # Same attribute. Are both values weighted?
        v1w = _WEIGHTED_ATTR.fullmatch(dn1_val)
        v2w = _WEIGHTED_ATTR.fullmatch(dn2_val)
        if v1w and v2w:
            (w1, dn1_val) = v1w.groups()
            (w2, dn2_val) = v2w.groups()
            if w1 != w2:
                return int(w1) - int(w2)
        elif (v1w or v2w) and not mix_weighted:
            raise AnsibleFilterError("Cannot compare weighted and unweighted values")
        if dn1_val < dn2_val:
            return -1
        elif dn1_val > dn2_val:
            return 1
    return len(dn1_rdns) - len(dn2_rdns)


def from_ldif(ldif_data):
    ''' Convert LDIF data to a list of dictionaries.

    Each LDIF entry will be converted to a dictionary containing a single-valued
    DN field, as well as a multi-valued field for each attribute.

    Args:
        ldif_data (str): a string containing UTF-8-encoded LDIF data

    Returns:
        The list of entries. Each entry is a dictionary with a single-valued
        "dn" key, as well as entries with lower-case keys and containing lists
        of values for all attributes present in the record.

    Throws:
        AnsibleFilterError: some problem occured while parsing the LDIF data. '''
    _check_lib()
    try:
        ldif_bytes = bytes(ldif_data, "utf-8")
    except TypeError:
        raise AnsibleFilterError("LDIF data expected")
    with BytesIO(ldif_bytes) as ldif_io:
        ldif_parser = ldif.LDIFRecordList(ldif_io)
        output = []
        try:
            ldif_parser.parse()
        except Exception as e:
            raise AnsibleFilterError(f"Failed to parse LDIF data: {e}")
        for dn, record in ldif_parser.all_records:
            out_obj = {"dn": dn}
            for attr, val in record.items():
                out_obj[attr.lower()] = [_try_utf8(v) for v in val]
            output.append(out_obj)
    return output


def to_ldif(data):
    ''' Convert a list of dictionaries representing records into LDIF data.

    Each entry in the input must contain at least one "dn" field. Other fields
    may be provided as strings or list of strings.

    Args:
        data (list): the list of records to convert

    Returns: the LDIF data as a string

    Throws:
        AnsibleError: the python-ldap library could not be found.
        AnsibleFilterTypeError: the data did not follow the expected structure.
        AnsibleFilterError: some problem occured while transforming the data to LDIF. '''
    _check_lib()
    if not isinstance(data, list):
        raise AnsibleFilterTypeError("List of records expected")

    # Pre-process the whole list
    processed_data = []
    for record in data:
        if not isinstance(record, dict):
            raise AnsibleFilterTypeError("Dictionary expected")

        if "dn" not in record:
            raise AnsibleFilterTypeError(f"Record {record} has no DN")
        if not isinstance(record["dn"], str):
            raise AnsibleFilterTypeError(f"In record {record}: DN is not a string")

        # Check and pre-process record
        processed_record = {}
        for k, v in record.items():
            if k == "dn":
                continue
            if not isinstance(k, str):
                raise AnsibleFilterTypeError(f"In record {record}: invalid attribute name")
            if isinstance(v, (str, int)):
                processed_record[k] = [str(v).encode()]
            elif isinstance(v, list):
                processed_record[k] = [str(e).encode() for e in v]
            else:
                raise AnsibleFilterTypeError(f"In record {record}: invalid attribute data for {k}")
        processed_data.append((record["dn"], processed_record))

    # Generate LDIF
    try:
        with StringIO() as output:
            ldif_writer = ldif.LDIFWriter(output)
            for args in processed_data:
                ldif_writer.unparse(*args)
            return output.getvalue()
    except Exception as e:
        raise AnsibleFilterError(f"Failed to generate LDIF ({e})")


def ldif_sort(data, allow_mix_weighted=False):
    ''' Sort LDIF data.

    This filter can be used to sort LDIF data based on their DNs. It does not
    support multi-valued RDNs.

    Args:
        data (list): the list of records to sort
        allow_mix_weighted (bool): whether comparing between weighted and unweighted
            attribute values will be allowed.

    Returns:
        The sorted LDIF data.

    Throws:
        AnsibleFilterError: if a multi-valued RDN is found or if unweighted and weighted
                            values are being compared. '''
    _check_lib()
    return sorted(data, key=functools.cmp_to_key(lambda a, b: _dn_compare(a, b, allow_mix_weighted)))


class FilterModule(object):
    def filters(self):
        return {
            'from_ldif': from_ldif,
            'to_ldif': to_ldif,
            'ldif_sort': ldif_sort,
        }
