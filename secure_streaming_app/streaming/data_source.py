"""
data_source.py

Provide a plaintext data generator. This module is to simulate a real-world data source (e.g. an IoT sensor)
It produces application-level messages that contain only application data. 

Provides a simple streaming-style data generator that produces structured plaintext messages before encryption. 
Each message is a dictionary as below:
    {"message": <str>}

This module is to simulate a real-word data source like an API without depending on an actual external API.
Rather than using an external API, a simple message has been done for ease of checking that it has encrypted and decrypted properly. 
"""

from typing import Dict

class DataSource:
    """
    A data generator that produces sequential messages. 

    For demonstrative purposes, placeholder messages to show encryption and decryption clearly during demo. 

    Attributes:
        counter (int): Internal counter for generating placeholder messages.
    """

    def __init__(self, start_value: int = 1):
        """
        Initialises the data generator. 

        Arguments:
            start_value (int): The initial value number for the data stream. Defaults to 1. 
        """
        self.counter = start_value

    def next_message(self) -> Dict[str, object]:
        """
        Produces the next message.

        Returns:
            dict: A plaintext message with the structure:

            {
                "message": <str>
            }

            The "message" field contains a simple placeholder string identifying this event in the sequence. 
        """
        message = {
            "message": f"Event {self.counter}"
        }

        self.counter += 1
        return message