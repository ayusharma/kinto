import colander

from cliquet import resource
from cliquet import schema
from cliquet.events import ResourceChanged
from pyramid.events import subscriber

from kinto.views import NameGenerator


class GroupSchema(schema.ResourceSchema):
    members = colander.SchemaNode(colander.Sequence(),
                                  colander.SchemaNode(colander.String()))


@resource.register(name='group',
                   collection_path='/buckets/{{bucket_id}}/groups',
                   record_path='/buckets/{{bucket_id}}/groups/{{id}}')
class Group(resource.ProtectedResource):

    mapping = GroupSchema()

    def __init__(self, *args, **kwargs):
        super(Group, self).__init__(*args, **kwargs)
        self.model.id_generator = NameGenerator()

    def get_parent_id(self, request):
        bucket_id = request.matchdict['bucket_id']
        parent_id = '/buckets/%s' % bucket_id
        return parent_id

    def collection_delete(self):
        """Override default behaviour to remove users principals in cascade
        when group is deleted.
        """
        filters = self._extract_filters()
        groups, _ = self.model.get_records(filters=filters)
        body = super(Group, self).collection_delete()
        permission_backend = self.request.registry.permission
        bucket_id = self.request.matchdict['bucket_id']
        remove_groups_from_principals(permission_backend, bucket_id, groups)
        return body

    def delete(self):
        group = self._get_record_or_404(self.record_id)
        permission_backend = self.request.registry.permission
        body = super(Group, self).delete()
        bucket_id = self.request.matchdict['bucket_id']
        remove_groups_from_principals(permission_backend, bucket_id, [group])
        return body


def remove_groups_from_principals(permission_backend, bucket_id, groups):
    """
    Remove groups from user principals.

    .. note::

        We can't use a ResourceChanged event because we need to access the
        ``members`` list which is not available in the deleted version
        (i.e. tombstone) of the record.
        A possible alternative would be to add a ``remove_principal(group_id)``
        method on the permission backend.
    """
    for group in groups:
        group_uri = '/buckets/%s/groups/%s' % (bucket_id, group['id'])
        for member in group['members']:
            permission_backend.remove_user_principal(member, group_uri)


@subscriber(ResourceChanged, for_resources=('group',),
            for_actions=('create', 'update'))
def on_group_changed(event):
    """Some groups were changed, update users principals.
    """
    for change in event.impacted_records:
        if 'old' in change:
            existing_record_members = set(change['old'].get('members', []))
        else:
            existing_record_members = set()

        group = change['new']
        group_uri = '/buckets/{bucket_id}/groups/{id}'.format(id=group['id'],
                                                              **event.payload)
        new_record_members = set(group.get('members', []))
        new_members = new_record_members - existing_record_members
        removed_members = existing_record_members - new_record_members

        permission_backend = event.request.registry.permission
        for member in new_members:
            # Add the group to the member principal.
            permission_backend.add_user_principal(member, group_uri)

        for member in removed_members:
            # Remove the group from the member principal.
            permission_backend.remove_user_principal(member, group_uri)
