package arweave

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// =============================================================================
// GraphQLQuery builder tests
// =============================================================================

func TestNewGraphQLQuery_Defaults(t *testing.T) {
	q := NewGraphQLQuery()
	query := q.Build()

	if !strings.Contains(query, "first: 10") {
		t.Error("default first should be 10")
	}
	if !strings.Contains(query, "sort: HEIGHT_DESC") {
		t.Error("default sort should be HEIGHT_DESC")
	}
}

func TestGraphQLQuery_AddTagFilter_SingleValue(t *testing.T) {
	q := NewGraphQLQuery().
		AddTagFilter("Root-CID", "bafyTestRootCID").
		SetFirst(5)

	query := q.Build()

	// Check the tag filter is present.
	if !strings.Contains(query, `name: "Root-CID"`) {
		t.Error("missing Root-CID tag name")
	}
	if !strings.Contains(query, `values: ["bafyTestRootCID"]`) {
		t.Error("missing Root-CID tag value")
	}
	if !strings.Contains(query, "first: 5") {
		t.Error("missing first: 5")
	}
}

func TestGraphQLQuery_AddTagFilter_MultipleValues(t *testing.T) {
	q := NewGraphQLQuery().
		AddTagFilter("Content-Type", "application/vnd.ipld.car", "base64-encoded-value")

	query := q.Build()

	if !strings.Contains(query, `values: ["application/vnd.ipld.car", "base64-encoded-value"]`) {
		t.Error("missing multiple OR values for Content-Type")
	}
}

func TestGraphQLQuery_MultipleTagFilters_AND(t *testing.T) {
	q := NewGraphQLQuery().
		AddTagFilter("Root-CID", "abc123").
		AddTagFilter("Protocol", "IPFS-Arweave-Bridge").
		AddTagFilter("Content-Type", "application/vnd.ipld.car")

	query := q.Build()

	// All three filters should be present (AND-ed).
	if !strings.Contains(query, `name: "Root-CID"`) {
		t.Error("missing Root-CID filter")
	}
	if !strings.Contains(query, `name: "Protocol"`) {
		t.Error("missing Protocol filter")
	}
	if !strings.Contains(query, `name: "Content-Type"`) {
		t.Error("missing Content-Type filter")
	}

	// Count occurrences - should have exactly 3 tag filter blocks.
	count := strings.Count(query, `{ name:`)
	if count != 3 {
		t.Errorf("expected 3 tag filters (AND), got %d", count)
	}
}

func TestGraphQLQuery_SetSort(t *testing.T) {
	q := NewGraphQLQuery().SetSort("HEIGHT_ASC")
	query := q.Build()

	if !strings.Contains(query, "sort: HEIGHT_ASC") {
		t.Error("missing sort: HEIGHT_ASC")
	}
	if strings.Contains(query, "sort: HEIGHT_DESC") {
		t.Error("should not contain HEIGHT_DESC")
	}
}

func TestGraphQLQuery_SetFirst_Zero(t *testing.T) {
	q := NewGraphQLQuery().SetFirst(0)
	query := q.Build()

	if strings.Contains(query, "first:") {
		t.Error("first should not appear when set to 0")
	}
}

func TestGraphQLQuery_SetFirst_Negative(t *testing.T) {
	q := NewGraphQLQuery().SetFirst(-1)
	query := q.Build()

	if strings.Contains(query, "first:") {
		t.Error("first should not appear when negative")
	}
}

func TestGraphQLQuery_EmptyFilters(t *testing.T) {
	q := NewGraphQLQuery()
	query := q.Build()

	// Should not contain the "tags:" block.
	if strings.Contains(query, "tags:") {
		t.Error("should not have tags block with no filters")
	}
	// But should still have first and sort.
	if !strings.Contains(query, "first: 10") {
		t.Error("should contain first")
	}
}

func TestGraphQLQuery_Build_Deterministic(t *testing.T) {
	q := NewGraphQLQuery().
		AddTagFilter("A", "1", "2").
		AddTagFilter("B", "3").
		SetFirst(8)

	q1 := q.Build()
	q2 := q.Build()

	if q1 != q2 {
		t.Error("Build() should be deterministic")
		t.Logf("q1: %s", q1)
		t.Logf("q2: %s", q2)
	}
}

func TestGraphQLQuery_ChainedSyntax(t *testing.T) {
	q := NewGraphQLQuery().
		AddTagFilter("Root-CID", "bafyXYZ").
		AddTagFilter("Content-Type", "application/vnd.ipld.car", "base64car").
		AddTagFilter("Protocol", "IPFS-Arweave-Bridge", "base64proto").
		SetFirst(8).
		SetSort("HEIGHT_DESC")

	query := q.Build()
	t.Logf("Built query:\n%s", query)

	// Basic sanity checks.
	if !strings.Contains(query, "Root-CID") {
		t.Error("missing Root-CID")
	}
	if !strings.Contains(query, "first: 8") {
		t.Error("missing first: 8")
	}
	if !strings.Contains(query, "sort: HEIGHT_DESC") {
		t.Error("missing sort")
	}
}

// =============================================================================
// RunGraphQL mock tests
// =============================================================================

func TestRunGraphQL_Mock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"transactions": {
						"edges": [
							{ "node": { "id": "tx-aaa" } },
							{ "node": { "id": "tx-bbb" } },
							{ "node": { "id": "tx-ccc" } }
						]
					}
				}
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	q := NewGraphQLQuery().
		AddTagFilter("Test-Tag", "test-value").
		SetFirst(3)

	ids, err := client.RunGraphQL(context.Background(), q)
	if err != nil {
		t.Fatalf("RunGraphQL failed: %v", err)
	}
	if len(ids) != 3 {
		t.Errorf("expected 3 IDs, got %d", len(ids))
	}
	if ids[0] != "tx-aaa" || ids[1] != "tx-bbb" || ids[2] != "tx-ccc" {
		t.Errorf("unexpected IDs: %v", ids)
	}
}

func TestRunGraphQL_EmptyResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":{"transactions":{"edges":[]}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	q := NewGraphQLQuery().AddTagFilter("NonExistent", "value")
	ids, err := client.RunGraphQL(context.Background(), q)
	if err != nil {
		t.Fatalf("RunGraphQL failed: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected 0 IDs, got %d", len(ids))
	}
}

func TestRunGraphQL_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	q := NewGraphQLQuery()
	_, err := client.RunGraphQL(context.Background(), q)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	t.Logf("Got expected error: %v", err)
}

// =============================================================================
// Verify QueryExistingCARs uses builder (integration-style)
// =============================================================================

func TestQueryExistingCARs_UsesBuilder(t *testing.T) {
	var receivedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.Method == "POST" {
			// Capture the query body to verify it uses the builder.
			body := make([]byte, 4096)
			n, _ := r.Body.Read(body)
			receivedQuery = string(body[:n])

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":{"transactions":{"edges":[]}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)
	_, err := client.QueryExistingCARs(context.Background(), "bafyTestCID", 5)
	if err != nil {
		t.Fatalf("QueryExistingCARs failed: %v", err)
	}

	// The query is JSON-encoded, so quotes are escaped as \".
	// Check for the JSON-escaped tag name patterns.
	if !strings.Contains(receivedQuery, `\"Root-CID\"`) {
		t.Error("generated query missing Root-CID filter")
	}
	if !strings.Contains(receivedQuery, `\"Content-Type\"`) {
		t.Error("generated query missing Content-Type filter")
	}
	if !strings.Contains(receivedQuery, `\"Protocol\"`) {
		t.Error("generated query missing Protocol filter")
	}
	if !strings.Contains(receivedQuery, "first: 5") {
		t.Error("generated query missing first: 5")
	}

	t.Logf("Generated query: %s", receivedQuery)
}

// =============================================================================
// Verify QueryExistingMetas uses builder
// =============================================================================

func TestQueryExistingMetas_UsesBuilder(t *testing.T) {
	var receivedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.Method == "POST" {
			body := make([]byte, 4096)
			n, _ := r.Body.Read(body)
			receivedQuery = string(body[:n])

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":{"transactions":{"edges":[]}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)
	_, err := client.QueryExistingMetas(context.Background(), "bafyTestCID", "data-tx-xyz", 3)
	if err != nil {
		t.Fatalf("QueryExistingMetas failed: %v", err)
	}

	// The query is JSON-encoded, so quotes are escaped as \".
	if !strings.Contains(receivedQuery, `\"Root-CID\"`) {
		t.Error("generated query missing Root-CID filter")
	}
	if !strings.Contains(receivedQuery, `\"IPFAR-Type\"`) {
		t.Error("generated query missing IPFAR-Type filter")
	}
	if !strings.Contains(receivedQuery, `\"Data-TXID\"`) {
		t.Error("generated query missing Data-TXID filter")
	}
	if !strings.Contains(receivedQuery, "first: 3") {
		t.Error("generated query missing first: 3")
	}

	t.Logf("Generated query: %s", receivedQuery)
}

func TestQueryExistingMetas_NoDataTXID(t *testing.T) {
	var receivedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.Method == "POST" {
			body := make([]byte, 4096)
			n, _ := r.Body.Read(body)
			receivedQuery = string(body[:n])

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":{"transactions":{"edges":[]}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)
	_, err := client.QueryExistingMetas(context.Background(), "bafyTestCID", "", 3)
	if err != nil {
		t.Fatalf("QueryExistingMetas failed: %v", err)
	}

	// Should NOT contain Data-TXID when empty.
	if strings.Contains(receivedQuery, "Data-TXID") {
		t.Error("generated query should not contain Data-TXID when empty")
	}

	t.Logf("Generated query (no Data-TXID): %s", receivedQuery)
}
