This project is implementing a REST API deployed on Google Cloud Platform.  

The eganmat_project.pdf document describes the steps to be taken in order to test the API, and also a description of API endpoints.

Testing was done using Postman to verify the API was performing correct.


## Project Description
Instructions
Your application needs to have one entity to model the user and at least two other non-user entities. The two non-user entities need to be related to each other and the user needs to be related to at least one of the non-user entities.

## Example
Looking back at the assignments you have done, let's consider Assignment 4

There were two entities Boat and Load. This would meet the requirement for two non-user entities.
These entities had a relationship between them - a boat can have zero, one or more loads on it. This meets the requirement that the two non-user entities must have a relationship with each other.
Assignment 4 didn't model users. If you were adapting Assignment 4 for this project, you would need to create an additional User entity.
Additionally for this project, you need a relationship between the User entity and a non-user entity. If you were to enhance Assignment 4 so that a boat is owned by a user, then there would be a relationship between the User and Boat entities . This meets the requirement of User entity being related to at least one of the non-user entities.
Note: It is up to you to decide what entities your application has and what is the relationship between them. You are free to adapt a previous assignment for this project or have an entirely different data model as long as the requirements are met.

## Requirements for non-user entities
For each entity a collection URL must be provided that is represented  by the collection name.
E.g.,  /boats represents the boats collection
The collection URL should show all the entities in the collection regardless of ownership and must not be a protected resource.
The collection URL for an entity must implement paging showing 5 entities at a time
At a minimum it must have a 'next' link on every page except the last
The collection must include a property that indicates how many total items are in the collection
Every representation of an entity must have a 'self' link pointing to the canonical representation of that entity
This must be a full URL, not relative path
Each entity must have at least 3 properties of its own.
id and self are not consider a property in this count.
Properties to model related entities are also no consider a property in this count.
E.g., a boat is not a property of a load in this count, and neither is the owner of a boat.
Properties that correspond to creation date and last modified date will be considered towards this count.
Every entity must support all 4 CRUD operations, i.e., create/add, read/get, update/edit and delete.
You must handle any "side effects" of these operations on an entity to other entities related to the entity.
E.g., Recall how you needed to update loads when deleting a boat.
Update for an entity should support both PUT and PATCH.
You must provide endpoints to create and remove relationship between the entities.
You only need to support JSON representations requests to endpoints that require a request body.
Requests to some endpoints, e.g., GET don't have a body. This point doesn't apply to such endpoints.
 Any response bodies should be in JSON.
Responses from some endpoints, e.g., DELETE, don't have a body. This point doesn't apply to such endpoints.
Any request to an endpoint that will send back a response with a body must include 'application/json' in the accept header. If it doesn't have such a header, such a request should be rejected.

## User Details
You must have a User entity in your database.
You must support the ability for users of the application to create user accounts. There is no requirement to edit or delete users.
You may choose from the following methods of handling user accounts
You can handle all account creation and authentication yourself.
You can use a 3rd party authentication service.
You must provide a URL where a user can provide a username and password to login or create a user account.
Requests for the REST API resources should use a JWT for authentication. So you must show the JWT to the user after the login.
There is no requirement for an integration at the UI level between the login page and the REST API endpoints.
One of the non-user entities must have a relationship with the user entity such that the entity is created by a user and can only be edited or deleted by the user who created it.
E.g., a boat may have an owner and only the owner who created it can edit or delete the boat, or add or remove a load from the boat.
You must provide a REST API endpoint so that a user can see all the instances of the non-user entity that were created by them.


## Status Codes
Your application should support at least the following status codes

200
201
204
401
403
405
406
