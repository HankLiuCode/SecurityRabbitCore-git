import unittest

def getList():
    return [1, 2, 4, 8]

class AssertTest(unittest.TestCase):
    def setUp(self):
        print("setUp Invoked")

    def tearDown(self):
        print("tearDown Invoked")

    def test_assert_true(self):
        self.assertTrue(getList() == [1, 2, 4, 8])

    def test_assert_equal(self):
        self.assertEqual(getList(), [1, 2, 4, 8])

    def test_assert_sequence_equal(self):
        self.assertListEqual(getList(), [1, 2, 4, 8])

if __name__ == '__main__':
    unittest.main()