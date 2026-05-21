package arweave

import (
	"context"
	"fmt"
	"strings"

	"github.com/LWDJD/ipfar-sdk/log"
)

// GraphQLQuery builds Arweave GraphQL queries for transactions.
// Use NewGraphQLQuery to create a new builder, then chain methods to
// configure tag filters, result limits, and sort order.
type GraphQLQuery struct {
	tagFilters []tagFilter
	first      int
	sort       string // "HEIGHT_DESC" or "HEIGHT_ASC"
}

// tagFilter represents a single tag condition: name AND any of the values (OR).
type tagFilter struct {
	Name   string
	Values []string // multiple values = OR condition
}

// NewGraphQLQuery creates a new query builder with sensible defaults
// (first=10, sort=HEIGHT_DESC).
func NewGraphQLQuery() *GraphQLQuery {
	return &GraphQLQuery{
		first: 10,
		sort:  "HEIGHT_DESC",
	}
}

// AddTagFilter adds a tag filter (name + one or more accepted values).
// Multiple AddTagFilter calls are AND-ed together.
// Multiple values per call are OR-ed (the gateway will match any of them).
func (q *GraphQLQuery) AddTagFilter(name string, values ...string) *GraphQLQuery {
	q.tagFilters = append(q.tagFilters, tagFilter{Name: name, Values: values})
	return q
}

// SetFirst sets the maximum number of results to return.
func (q *GraphQLQuery) SetFirst(n int) *GraphQLQuery {
	q.first = n
	return q
}

// SetSort sets the sort order.  Valid values are "HEIGHT_DESC" (default)
// and "HEIGHT_ASC".
func (q *GraphQLQuery) SetSort(order string) *GraphQLQuery {
	q.sort = order
	return q
}

// Build returns the complete GraphQL query string ready for POST /graphql.
func (q *GraphQLQuery) Build() string {
	var sb strings.Builder
	sb.WriteString("{\n\t\ttransactions(\n")

	if len(q.tagFilters) > 0 {
		sb.WriteString("\t\t\ttags: [\n")
		for i, tf := range q.tagFilters {
			sb.WriteString("\t\t\t\t{ name: ")
			sb.WriteString(fmt.Sprintf("%q", tf.Name))
			sb.WriteString(", values: [")
			for j, v := range tf.Values {
				if j > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString(fmt.Sprintf("%q", v))
			}
			sb.WriteString("] }")
			if i < len(q.tagFilters)-1 {
				sb.WriteString(",")
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\t\t\t],\n")
	}

	if q.first > 0 {
		sb.WriteString(fmt.Sprintf("\t\t\tfirst: %d,\n", q.first))
	}

	sb.WriteString(fmt.Sprintf("\t\t\tsort: %s\n", q.sort))
	sb.WriteString("\t\t) {\n\t\t\tedges {\n\t\t\t\tnode { id }\n\t\t\t}\n\t\t}\n\t}")

	return sb.String()
}

// RunGraphQL executes the query against the gateway and returns transaction IDs.
func (gc *GatewayClient) RunGraphQL(ctx context.Context, query *GraphQLQuery) ([]string, error) {
	q := query.Build()
	log.Debug(ctx, "GraphQL query: %s", q)
	return gc.runGraphQLQuery(ctx, q)
}
