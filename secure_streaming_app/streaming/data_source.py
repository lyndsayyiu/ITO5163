"""
data_source.py

Provides a simple streaming-style data generator that produces structured plaintext messages before encryption. 
Each message is a dictionary as below:
    {"seq": <int>, "message": <str>}

This module is to simulate a real-word data source like an API without depending on an actual external API.
Rather than using an external API, a simple message has been done for ease of checking that it has encrypted and decrypted properly. 
"""

import time
from typing import Dict, Optional

class DataSource:
    """
    A data generator that produces sequential messages. 

    Attributes:
        seq (int): The current sequence number. Increments with each message generated.
    """

    def __init__(self, start_seq: int = 1):
        """
        Initialises the data source.

        Arguments:
            start_seq (int): The initial sequence number for the data stream. Defaults to 1. 
        """
        self.seq = start_seq

    def next_message(self) -> Dict[str, object]:
        """
        Generates the next sequential message. 

        Returns:
            dict: A plaintext message with the structure:

            {
                "seq": <int>,
                "message": <str>
            }

            The "message" field contains a simple placeholder string identifying this event in the sequence. 
        """
        message = {
            "seq": self.seq,
            "message": f"{self.seq}"
        }

        self.seq += 1
        return message