from __future__ import absolute_import
def test_suite():
    import doctest
    return doctest.DocFileSuite("store.txt",
            optionflags=doctest.REPORT_ONLY_FIRST_FAILURE)

