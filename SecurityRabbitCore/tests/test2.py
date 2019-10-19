import unittest

def fun2(x):
    return x + 2

class MyTest2(unittest.TestCase):
    def test(self):
        self.assertEqual(fun2(3),5)
