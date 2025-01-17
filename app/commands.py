import typer
import asyncio
import requests
import json
from enum import Enum
from app.db.session import get_session
from app.apis.v1.saml_auth.models import Role

from app.apis.v1.utils import get_keycloak_admin

cli = typer.Typer()

class SeedOperation(str, Enum):
    """Available seeding operations"""
    ALL = "all"
    REALM_ROLES = "realm_roles"
    CLIENT_ROLES = "client_roles"
    BIND_ADMIN = "bind_admin"
    BIND_ALL = "bind_all"
    STORE_REALM_ROLES = "store_realm_roles"

class Environment(str, Enum):
    development = "development"
    testing = "testing"
    production = "production"
    
realm_roles = [
    "Supervisor (Zoodmall)",
    "Team Leader (Zoodmall)",
    "Agent (Zoodmall)",
    "Agent",
    "Supervisor",
    "Marketeer",
    "Developer",
    "Admin"
]

# Client Roles
client_roles = [
    ("Read Access on Bot Building", "read:bot_building"),
    ("Read Access on Data Lab", "read:data_lab"),
    ("Read Access on Custom API", "read:custom_api"),
    ("Read Access on Audience", "read:audience"),
    ("Read Access on Settings", "read:settings"),
    ("Read Access on Conversation", "read:conversation"),
    ("Read Access on Analytics", "read:analytics"),
    ("Write Access on Bot Building", "write:bot_building"),
    ("Write Access on Data Lab", "write:data_lab"),
    ("Write Access on Custom API", "write:custom_api"),
    ("Write Access on Settings", "write:settings"),
    ("Write Access on Conversation", "write:conversation"),
    ("CRM Supervisor Access", "generic:crm_supervisor"),
    ("Can Create Inbox Tags", "write:inbox_tag"),
    ("Can View and Use Inbox Tags", "read:inbox_tag"),
    ("Read Access on NLP Integrations", "read:nlp_integration"),
    ("Write Access on NLP Integrations", "write:nlp_integration"),
    ("Read Access on Ecommerce Integration", "read:ecommerce_integration"),
    ("Write Access on Ecommerce Integration", "write:ecommerce_integration"),
    ("Read Channel", "read:channel_integration"),
    ("write channel", "write:channel_integration"),
    ("write remove channel", "write:channel_disconnect"),
    ("Read Access on Broadcast", "read:broadcast"),
    ("Write Access on Broadcast", "write:broadcast"),
    ("Can View Settings Tags", "read:settings_tag"),
    ("Can View Settings Saved Reply", "read:settings_saved_reply"),
    ("Can View Settings Team Information", "read:settings_team_information"),
    ("Can View Settings User Management", "read:settings_user_management"),
    ("Can View Group Management", "read:settings_group_management"),
    ("Can Write Settings Tags", "write:settings_tag"),
    ("Can Write Settings Saved Reply", "write:settings_saved_reply"),
    ("Can Write Settings Team Information", "write:settings_team_information"),
    ("Can Write Settings User Management", "write:settings_user_management"),
    ("Can Write Settings Group Management", "write:settings_group_management"),
    ("Can Export Audience", "write:audience"),
    ("Read: automation", "read:workflow_automation"),
    ("write: automation", "write:workflow_automation"),
    ("Read Access on Inbox Unassigned Queue", "read:inbox_unassigned_queue"),
    ("Read Access on Inbox Unassigned Queue", "read:inbox_bot_queue"),
    ("Delete Access on DataLab", "delete:data_lab"),
    ("Can Read Settings Ticket Configuration", "read:settings_ticket_configuration"),
    ("Can Read Settings Business Hour", "read:settings_business_hour"),
    ("Can Read Settings SLA Configuration", "read:settings_sla_configuration"),
    ("Can Write Settings Ticket Configuration", "write:settings_ticket_configuration"),
    ("Can Write Settings Business Hour", "write:settings_business_hour"),
    ("Can Write Settings SLA Configuration", "write:settings_sla_configuration")
]

ROLE_PERMISSIONS = {
    "Developer": [
        "read:bot_building",
        "read:data_lab",
        "read:custom_api",
        "read:audience",
        "read:analytics",
        "write:bot_building",
        "write:data_lab",
        "write:custom_api",
        "delete:data_lab"
    ],
    "Supervisor": [
        "read:bot_building",
        "read:data_lab",
        "read:custom_api",
        "read:audience",
        "read:settings",
        "read:conversation",
        "read:analytics",
        "write:bot_building",
        "write:data_lab",
        "write:custom_api",
        "write:settings",
        "write:conversation",
        "generic:crm_supervisor",
        "write:inbox_tag",
        "read:inbox_tag",
        "read:inbox_unassigned_queue",
        "read:inbox_bot_queue"
    ],
    "Agent": [
        "read:audience",
        "read:conversation",
        "read:analytics",
        "write:conversation",
        "read:inbox_tag",
        "read:settings_tag",
        "read:settings_saved_reply",
        "read:inbox_unassigned_queue",
        "read:inbox_bot_queue"
    ],
    "Marketeer": [
        "read:bot_building",
        "read:data_lab",
        "read:custom_api",
        "read:audience",
        "read:analytics",
        "write:bot_building",
        "read:broadcast",
        "write:broadcast"
    ],
    "Agent (Zoodmall)": [
        "read:conversation",
        "write:conversation",
        "read:settings_tag",
        "read:settings_saved_reply",
        "read:inbox_unassigned_queue",
        "read:inbox_bot_queue"
    ],
    "Team Leader (Zoodmall)": [
        "read:audience",
        "read:settings",
        "read:conversation",
        "read:analytics",
        "write:settings",
        "write:conversation",
        "generic:crm_supervisor",
        "write:inbox_tag",
        "read:inbox_tag",
        "read:inbox_unassigned_queue",
        "read:inbox_bot_queue"
    ],
    "Supervisor (Zoodmall)": [
        "read:bot_building",
        "read:data_lab",
        "read:settings",
        "read:conversation",
        "read:analytics",
        "write:settings",
        "write:conversation",
        "generic:crm_supervisor",
        "write:inbox_tag",
        "read:inbox_tag",
        "read:settings_tag",
        "read:settings_saved_reply",
        "read:settings_user_management",
        "read:settings_group_management",
        "write:settings_tag",
        "write:settings_saved_reply",
        "write:settings_user_management",
        "write:settings_group_management",
        "read:inbox_unassigned_queue",
        "read:inbox_bot_queue"
    ]
}
    
class Keycloak():
    def __init__(self):
        self.access_token = None  # Initialize as None
        self.keycloak_url = "http://localhost:8080"
        self.keycloak_client_id = "12bd07fe-8878-4239-85dd-fa3af3028c01"
    
    async def initialize(self):
        self.access_token = await get_keycloak_admin()
        return self

    def create_realm_level_role(self):
        url = f"{self.keycloak_url}/admin/realms/sso-realm/partialImport"
    
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        roles_data = []
        for role in realm_roles:
            roles_data.append({
                "name": role,
                "description": f"Realm role for {role}"
            })
        payload = {
            "roles": {
                "realm": roles_data
            }
        }

        response = requests.post(url, headers=headers, json=payload)
        if response.status_code == 200:
            print("Realm roles created successfully")
        else:
            print(f"Failed to create realm roles: {response.status_code} - {response.text}")
            
    def create_client_level_roles(self):
        url = f"{self.keycloak_url}/admin/realms/sso-realm/clients/{self.keycloak_client_id}/roles"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        for role in client_roles:
            response = requests.post(url, headers=headers, json={
                "name": role[1],
                "description": f"Client role for {role[0]}"
            })
            if response.status_code == 201:
                print("Client roles created successfully")
            else:
                print(f"Failed to create client roles: {response.status_code} - {response.text}")
                
    def get_client_roles(self):
        url = f"{self.keycloak_url}/admin/realms/sso-realm/clients/{self.keycloak_client_id}/roles"
        headers = {
            "Authorization": f"Bearer {self.access_token}"
        }    
        response = requests.get(url, headers=headers)
        return response.json()
    
    def add_composite_roles(self, role_name, roles_to_bind):
        url = f"{self.keycloak_url}/admin/realms/sso-realm/roles/{role_name}/composites"
    
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(url, headers=headers, json=roles_to_bind)
        return response
    
    def bind_client_roles_for_role(self, role_name, permissions):
        # Get all client roles
        client_roles = self.get_client_roles()
        
        # Filter roles based on permissions for this role
        roles_to_bind = [
            {
                "id": role["id"],
                "name": role["name"],
                "composite": False,
                "clientRole": True,
                "containerId": self.keycloak_client_id
            }
            for role in client_roles
            if role["name"] in permissions
        ]
        
        print(f"\nBinding roles for {role_name}:")
        print(json.dumps(roles_to_bind, indent=4))
        
        # Add composite roles to the specified role
        if roles_to_bind:
            response = self.add_composite_roles(
                role_name,
                roles_to_bind
            )
            
            if response.status_code == 204:
                print(f"Successfully bound {len(roles_to_bind)} client roles to {role_name} role")
                print("Bound roles:")
                for role in roles_to_bind:
                    print(f"- {role['name']}")
            else:
                print(f"Failed to bind roles for {role_name}. Status code: {response.status_code}")
                print(f"Response: {response.text}")
        else:
            print(f"No roles to bind for {role_name}")
            
    def bind_roles(self):
        for role_name, permissions in ROLE_PERMISSIONS.items():
            self.bind_client_roles_for_role(role_name, permissions)

    def bind_admin_roles(self):
        client_roles = self.get_client_roles()
        roles_to_bind = [
            {
                "id": role["id"],
                "name": role["name"],
                "composite": False,
                "clientRole": True,
                "containerId": self.keycloak_client_id
            }
            for role in client_roles
            if role["name"] != 'uma_protection'
        ]
        if roles_to_bind:
            response = self.add_composite_roles(
                "Admin",
                roles_to_bind
            )
            
            if response.status_code == 204:
                print(f"Successfully bound {len(roles_to_bind)} client roles to Admin role")
                print("Bound roles:")
                for role in roles_to_bind:
                    print(f"- {role['name']}")
            else:
                print(f"Failed to bind roles for Admin. Status code: {response.status_code}")
                print(f"Response: {response.text}")
        else:
            print(f"No roles to bind for Admin")
            
    def get_realm_level_roles(self):
        url = f"{self.keycloak_url}/admin/realms/sso-realm/roles"
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        expected_realm_roles = []
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            keycloak_realm_roles = response.json()
            for role in keycloak_realm_roles:
                if role.get('name') in realm_roles:
                    expected_realm_roles.append({
                        "id": role.get('id'),
                        "role_name": role.get('name')
                    })
            return expected_realm_roles

def create_realm_level_roles(environment: Environment):
    async def async_create_roles():
        keycloak = await Keycloak().initialize()
        keycloak.create_realm_level_role()
    
    asyncio.run(async_create_roles())
    
def create_client_level_roles(environment: Environment):
    async def async_create_client_roles():
        keycloak = await Keycloak().initialize()
        keycloak.create_client_level_roles()
    
    asyncio.run(async_create_client_roles())
    
def bind_roles(environment: Environment, role_name: str = None):
    async def async_bind_roles():
        keycloak = await Keycloak().initialize()
        if role_name == "Admin":
            keycloak.bind_admin_roles()
        else:
            keycloak.bind_roles()
    
    asyncio.run(async_bind_roles())


def store_realm_roles(environment: Environment):
    """Store Keycloak realm roles in the database"""
    async def async_store_roles():
        keycloak = await Keycloak().initialize()
        realm_roles = keycloak.get_realm_level_roles()
        async for db in get_session():
            try:   
                roles = [
                    Role(
                        role_keycloak_uid=role.get('id'), 
                        role_name=role.get('role_name')
                    ) 
                    for role in realm_roles
                ]
                db.add_all(roles)
                await db.commit()
                print("Successfully stored realm roles in database")
            
            except Exception as e:
                print(f"Error storing realm roles: {str(e)}")
                await db.rollback()
                raise
    
    asyncio.run(async_store_roles())

@cli.command()
def seed(
    environment: Environment = Environment.development,
    operation: SeedOperation = SeedOperation.ALL
):
    """
    Seed the database and Keycloak roles
    
    Args:
        environment: The target environment for seeding
        operation: Specific operation to perform (default: all)
    """
    operations = {
        SeedOperation.ALL: lambda: (
            create_realm_level_roles(environment),
            create_client_level_roles(environment),
            bind_roles(environment, "Admin"),
            bind_roles(environment),
            store_realm_roles(environment)
        ),
        SeedOperation.REALM_ROLES: lambda: create_realm_level_roles(environment),
        SeedOperation.CLIENT_ROLES: lambda: create_client_level_roles(environment),
        SeedOperation.BIND_ADMIN: lambda: bind_roles(environment, "Admin"),
        SeedOperation.BIND_ALL: lambda: bind_roles(environment),
        SeedOperation.STORE_REALM_ROLES: lambda: store_realm_roles(environment)
    }
    
    if operation == SeedOperation.ALL:
        operations[operation]()
    else:
        print(f"Executing {operation.value}...")
        operations[operation]()

if __name__ == "__main__":
    cli()