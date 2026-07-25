import time
import pandas as pd

class StreamEngine:
    def __init__(self, data):
        self.data  = data
        self.index = 0

    def get_next(self):
        if self.index >= len(self.data):
            self.index = 0
        row = self.data.iloc[[self.index]]
        self.index += 1
        time.sleep(0.2)
        return row
