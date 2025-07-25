Changes
-------
* v0.4.0+bgh:

  - Refactor IniStorage.get method to improve Azure resource handling
    and error management. This change ensures that the method can
    handle different Azure resources (Key Vault, App Configuration,
    local INI file) more effectively, providing better error messages
    and handling missing settings gracefully.

* v0.4.0+dev:

  - Added bulksalesitemprices, salespricelistperiods, salespricelists,
    salespricelistvolumediscounts, supplieritems, syncsalesitemprices,
    by Sascha Dobbelaere (@sdobbelaere).

* v0.4.0:

  - Added ratelimiter, requested and tested by various people.

  - Added debug logs, by Martijn Hemeryck (@mhemeryck).

  - Cleanup. Also by Eike Dehling (@EikeDehling).

* v0.3.6:

  - Try refreshing tokens *before* receiving a 401 per the request of
    Alexandar Mechev (@apmechev).

* v0.3.5:

  - Implement quotations. Thanks Ties (@ties-v).

  - Updated/added assets, tests and docs.

* v0.3.4:

  - Added bankaccounts manager. Closes #21. Thanks Edwin van de Ven
    (@edwinvandeven).

  - Added global configurable iteration limit parameter.

    Default unpagination was limited to 50 to avoid infinite loops in
    case of bugs or bad data. Some users require more pages of output.

    Set the iteration_limit in your config storage to a higher value if
    you run into "Iteration ... limit reached!".

    Closes #22. Thanks George Viorel Visniuc (@gvisniuc).

  - Move storage/config backends to separate storage subdir. This way we
    don't require the configparse if you're not using the IniStorage.
    Shows a DeprecationWarning so you have time to update your code.

    Closes #19.

* v0.3.3:

  - Additions to ExactInvoice element:

    + Add optional "month" to get_ledger_lines() for accrued/deferred
      income.
    + Add get_vatcode_for_ledger_line() for customizable VATCodes.

* v0.3.2:

  - Fix ConfigParser deprecationwarning.
  - Add VatCodes API support. Thanks Stani Michiels (@stanim). Closes
    #12.

* v0.3.1:

  - Add Contacts API support. Thanks @Imperatus. Closes #8 and #11.

* v0.3.0:

  - Refactor code to use fewer arguments. This makes the BetterCodeHub
    checks happy and that makes me happy. This is a BACKWARDS
    INCOMPATIBLE CHANGE. All your code that looked like this::

        ret = self.rest('GET', 'v1/current/Me?$select=CurrentDivision')

    will have to be changed to this::

        from exactonline.resource import GET
        ret = self.rest(GET('v1/current/Me?$select=CurrentDivision'))

    Closes #7.

  - Add IniStorage default return value for get_default_url(), returning
    get_base_url(). This makes life easier for those who did not read
    the README. Closes #6.

* v0.2.5:

  - Fix set_tokens() bug in Python3; make sure json.loads() gets an
    unistr. Reported by @Imperatus, @LordGaav. Closes #9 and #10.

* v0.2.4:

  - Improve HTTP functions for better error reporting and better Py23
    compatibility.

* v0.2.3:

  - Add api.invoices.filter(invoice_number__in=LIST) filter.
  - Iterate over resultsets instead of using recursion (api.unwrap).
  - Fix python3 compatibility issue: bytestring found on autorefresh.
    Thanks @wpxgit.

* v0.2.2:

  - Correct RST source in CHANGES file. Did not display properly on
    PyPI.

* v0.2.1:

  - Correct example Python code in docs. Thanks @alexBaizeau.
  - Add ``exactonline.elements`` that were missing in the 0.2.0
    distributed package. Thanks @hcwsegers.
  - Add overridable ``get_ledger_code_to_guid_maps()`` helper to the
    invoices elements class.

* v0.2.0:

  - Update build/PyPI info: move to Stable, add Python 3.4 and 3.5
    version, fix Python 3 compatibility.
  - Fix a few README RST issues. Update OAuth documentation.
  - Add initial ``exactonline.elements`` to use for easier object
    oriented data submissions.
  - Add and improve SSL, API and Python3 tests.

* v0.1.3:

  - Add ``receivables`` manager to the API. This manager allows you to
    build a list similar to the *Outstanding Receivables* page of
    *Financial Reporting*.
  - Add ``api.invoices.map_exact2foreign_invoice_numbers`` and
    ``api.invoices.map_foreign2exact_invoice_numbers`` methods to
    quickly get a mapping between our own and the ExactOnline invoice
    numbers.
  - Python3 compatibility.
  - Minor fixes.
