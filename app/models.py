# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
"""
This models.py file contains functions related to queries to add data to DB (user, Relying Party, access_certificate).

"""
import pymysql
from app_config.config import ConfService
from db import get_db_connection as conn

from app import logger

def check_user(hash_pid, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT user_id
                FROM user
                WHERE hash_pid = %s
            """
            
            cursor.execute(select_query, (hash_pid,))
            result = cursor.fetchone()
            
            if result:
                user_id = result[0]
                extra = {'code': log_id}
                logger.info(f"User, {user_id}, already exists.", extra=extra)
                print(f"User, {user_id}, already exists.")
                return user_id
            else:
                extra = {'code': log_id}
                logger.info("User with hash_pid not found.", extra=extra)
                print("User with hash_pid not found.")
                return None
        else:
            return None

    except pymysql.MySQLError as e:
        extra = {'code': log_id}
        logger.error(f"Error checking user: {e}", extra=extra)
        print(f"Error checking user: {e}")
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()

def insert_user(hash_pid, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            insert_query = "INSERT INTO user (hash_pid) VALUES (%s)"
            
            cursor.execute(insert_query, (hash_pid,))
            
            connection.commit()
            
            extra = {'code': log_id} 
            logger.info(f"User successfully added. New user ID: {cursor.lastrowid}", extra=extra)

            print(f"User successfully added. New user ID: {cursor.lastrowid}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error inserting user: {e}", extra=extra)
        print(f"Error inserting user: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()

def insert_relying_party(country, name, registration_number, common_name, contacts, user_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            insert_query = """
            INSERT INTO relying_party (country, name, registration_number, common_name, contacts, user_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            """
            
            cursor.execute(insert_query, (country, name, registration_number, common_name, contacts, user_id))
            connection.commit()

            extra = {'code': log_id} 
            logger.info(f"Relying Party successfully added. New Relying Party ID: {cursor.lastrowid}", extra=extra)
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error inserting Relying Party: {e}", extra=extra)
        print(f"Error inserting Relying Party: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()

def insert_access_certificate(intended_use, certificate, certificate_issuer, certificate_distinguished_name, 
                              validity_from, validity_to, serial_number, status, dns_name ,user_id, relyingParty_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            insert_query = """
            INSERT INTO access_certificate (intended_use, certificate, certificate_issuer, certificate_distinguished_name, 
                                            validity_from, validity_to, serial_number, status, DNS_name, user_id, relyingParty_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            cursor.execute(insert_query, (intended_use, certificate, certificate_issuer, certificate_distinguished_name, 
                                          validity_from, validity_to, serial_number, status, dns_name, user_id, relyingParty_id))
            connection.commit()

            
            extra = {'code': log_id} 
            logger.info(f"Access Certificate successfully created. New Certificate ID: {cursor.lastrowid}", extra=extra)
            print(f"Access Certificate successfully created. New Certificate ID: {cursor.lastrowid}")

    except pymysql.MySQLError as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error inserting Access Certificate: {e}", extra=extra)
        print(f"Error inserting Access Certificate: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()

def get_user_id_by_hash_pid(hash_pid, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT user_id
                FROM user
                WHERE hash_pid = %s
            """
            
            cursor.execute(select_query, (hash_pid,))
            
            result = cursor.fetchone()

            if result:
                user_id = result[0]
                
                extra = {'code': log_id} 
                logger.info(f"User found: {cursor.lastrowid}.", extra=extra)
                return user_id
            else:
                extra = {'code': log_id} 
                logger.info(f"No user found with the hash_pid.", extra=extra)
                print(f"No user found with the hash_pid.")
                return None

    except pymysql.MySQLError as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error fetching user_id: {e}", extra=extra)
        print(f"Error fetching user_id: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()


def get_relying_party_names_by_user_id(user_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT name, relyingParty_id
                FROM relying_party
                WHERE user_id = %s
            """
            
            cursor.execute(select_query, (user_id,))
            
            result = cursor.fetchall()

            if result: 
                relying_party_data = [
                    {"name": row[0], "relyingParty_id": row[1]} 
                    for row in result
                ]
                extra = {'code': log_id} 
                logger.info(f"Name found for the user_id: {user_id}", extra=extra)
                return relying_party_data
            else:
                extra = {'code': log_id} 
                logger.info(f"No name found for the user_id: {user_id}", extra=extra)
                print(f"No name found for the user_id: {user_id}")
            

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error fetching relying party names: {e}", extra=extra)
        print(f"Error fetching relying party names: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()

def get_access_certificate_by_user_id_by_relying_party_id(user_id, relyingParty_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT serial_number, certificate_issuer, certificate_distinguished_name, validity_from, validity_to, accessCertificate_id, status
                FROM access_certificate
                WHERE user_id = %s AND relyingParty_id = %s
            """
            
            cursor.execute(select_query, (user_id,relyingParty_id,))
            
            result = cursor.fetchall()

            if result:
                access_certificate_data = [
                    {"serial_number": row[0], "certificate_issuer": row[1], "certificate_distinguished_name": row[2], "validity_from": row[3], "validity_to": row[4], "accessCertificate_id": row[5], "status": row[6]} 
                    for row in result
                ]
                
                extra = {'code': log_id} 
                logger.info(f"Certificate found for the user_id: {user_id}", extra=extra)
                return access_certificate_data
            else:
                print(f"No certificate found for the user_id: {user_id}")

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error: {e}", extra=extra)
        print(f"Error: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()

def update_access_certificate_status(accessCertificate_id, new_status, log_id):
    try:
        if new_status not in ['active', 'revoke']:
            extra = {'code': log_id}
            logger.info(f"Invalid status: {new_status}. Must be 'active' or 'revoke'.", extra=extra)
            print(f"Invalid status: {new_status}. Must be 'active' or 'revoke'.")
            return False

        connection = conn()
        if connection:
            cursor = connection.cursor()

            update_query = """
                UPDATE access_certificate
                SET status = %s
                WHERE accessCertificate_id = %s
            """
            
            cursor.execute(update_query, (new_status, accessCertificate_id))
            connection.commit()

            if cursor.rowcount > 0:
                extra = {'code': log_id}
                logger.info(f"Certificate {accessCertificate_id} status successfully updated to '{new_status}'", extra=extra)
                print(f"Certificate {accessCertificate_id} status successfully updated to '{new_status}'")
                return True
            else:
                extra = {'code': log_id}
                logger.info(f"No certificate found with ID {accessCertificate_id}.", extra=extra)
                print(f"No certificate found with ID {accessCertificate_id}.")
                return False

    except pymysql.MySQLError as e:
        extra = {'code': log_id}
        logger.error(f"Error updating status: {e}", extra=extra)
        print(f"Error updating status: {e}")
        return False
    finally:
        if connection:
            cursor.close()
            connection.close()


# insert_user("123abc456hashPIDtest")
# insert_relying_party("Portugal", "Empresa ABC", "123456789", "Common Name XYZ", "contact@example.com", 1)
# insert_access_certificate("Use description", "Certificate data", "Issuer XYZ", "DN XYZ", "2024-01-01", "2025-01-01", "12345", "active", 1, 1)