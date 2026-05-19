import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { z } from "zod";
import * as pipedrive from "pipedrive";
import * as dotenv from 'dotenv';
import Bottleneck from 'bottleneck';
import jwt from 'jsonwebtoken';
import http from 'http';

// Type for error handling
interface ErrorWithMessage {
  message: string;
}

function isErrorWithMessage(error: unknown): error is ErrorWithMessage {
  return (
    typeof error === 'object' &&
    error !== null &&
    'message' in error &&
    typeof (error as Record<string, unknown>).message === 'string'
  );
}

function getErrorMessage(error: unknown): string {
  if (isErrorWithMessage(error)) {
    return error.message;
  }
  return String(error);
}

// Load environment variables
dotenv.config();

// Check for required environment variables
if (!process.env.PIPEDRIVE_API_TOKEN) {
  console.error("ERROR: PIPEDRIVE_API_TOKEN environment variable is required");
  process.exit(1);
}

if (!process.env.PIPEDRIVE_DOMAIN) {
  console.error("ERROR: PIPEDRIVE_DOMAIN environment variable is required (e.g., 'ukkofi.pipedrive.com')");
  process.exit(1);
}

const jwtSecret = process.env.MCP_JWT_SECRET;
const jwtAlgorithm = (process.env.MCP_JWT_ALGORITHM || 'HS256') as jwt.Algorithm;
const jwtVerifyOptions = {
  algorithms: [jwtAlgorithm],
  audience: process.env.MCP_JWT_AUDIENCE,
  issuer: process.env.MCP_JWT_ISSUER,
};

if (jwtSecret) {
  const bootToken = process.env.MCP_JWT_TOKEN;
  if (!bootToken) {
    console.error("ERROR: MCP_JWT_TOKEN environment variable is required when MCP_JWT_SECRET is set");
    process.exit(1);
  }

  try {
    jwt.verify(bootToken, jwtSecret, jwtVerifyOptions);
  } catch (error) {
    console.error("ERROR: Failed to verify MCP_JWT_TOKEN", error);
    process.exit(1);
  }
}

const verifyRequestAuthentication = (req: http.IncomingMessage) => {
  if (!jwtSecret) {
    return { ok: true } as const;
  }

  const header = req.headers['authorization'];
  if (!header) {
    return { ok: false, status: 401, message: 'Missing Authorization header' } as const;
  }

  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return { ok: false, status: 401, message: 'Invalid Authorization header format' } as const;
  }

  try {
    jwt.verify(token, jwtSecret, jwtVerifyOptions);
    return { ok: true } as const;
  } catch (error) {
    return { ok: false, status: 401, message: 'Invalid or expired token' } as const;
  }
};

const limiter = new Bottleneck({
  minTime: Number(process.env.PIPEDRIVE_RATE_LIMIT_MIN_TIME_MS || 250),
  maxConcurrent: Number(process.env.PIPEDRIVE_RATE_LIMIT_MAX_CONCURRENT || 2),
});

const withRateLimit = <T extends object>(client: T): T => {
  return new Proxy(client, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (typeof value === 'function') {
        return (...args: unknown[]) => limiter.schedule(() => (value as Function).apply(target, args));
      }
      return value;
    },
  });
};

// Initialize Pipedrive API client with API token and custom domain
const apiClient = new pipedrive.ApiClient();
apiClient.basePath = `https://${process.env.PIPEDRIVE_DOMAIN}/api/v1`;
apiClient.authentications = apiClient.authentications || {};
apiClient.authentications['api_key'] = {
  type: 'apiKey',
  'in': 'query',
  name: 'api_token',
  apiKey: process.env.PIPEDRIVE_API_TOKEN
};

// Initialize Pipedrive API clients
const dealsApi = withRateLimit(new pipedrive.DealsApi(apiClient));
const personsApi = withRateLimit(new pipedrive.PersonsApi(apiClient));
const organizationsApi = withRateLimit(new pipedrive.OrganizationsApi(apiClient));
const pipelinesApi = withRateLimit(new pipedrive.PipelinesApi(apiClient));
const itemSearchApi = withRateLimit(new pipedrive.ItemSearchApi(apiClient));
const leadsApi = withRateLimit(new pipedrive.LeadsApi(apiClient));
// @ts-ignore - ActivitiesApi exists but may not be in type definitions
const activitiesApi = withRateLimit(new pipedrive.ActivitiesApi(apiClient));
// @ts-ignore - NotesApi exists but may not be in type definitions
const notesApi = withRateLimit(new pipedrive.NotesApi(apiClient));
// @ts-ignore - UsersApi exists but may not be in type definitions
const usersApi = withRateLimit(new pipedrive.UsersApi(apiClient));

// Create MCP server
const server = new McpServer({
  name: "pipedrive-mcp-server",
  version: "1.1.0",
  capabilities: {
    resources: {},
    tools: {},
    prompts: {}
  }
});

// === TOOLS ===

// Get all users (for finding owner IDs)
server.tool(
  "get-users",
  "Get all users/owners from Pipedrive to identify owner IDs for filtering deals",
  {},
  async () => {
    try {
      const response = await usersApi.getUsers();
      const users = response.data?.map((user: any) => ({
        id: user.id,
        name: user.name,
        email: user.email,
        active_flag: user.active_flag,
        role_name: user.role_name
      })) || [];

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            summary: `Found ${users.length} users in your Pipedrive account`,
            users: users
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error fetching users:", error);
      return {
        content: [{
          type: "text",
          text: `Error fetching users: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get deals with flexible filtering options
server.tool(
  "get-deals",
  "Get deals from Pipedrive with flexible filtering options including search by title, date range, owner, stage, status, and more. Use 'get-users' tool first to find owner IDs.",
  {
    searchTitle: z.string().optional().describe("Search deals by title/name (partial matches supported)"),
    daysBack: z.number().optional().describe("Number of days back to fetch deals based on last activity date (default: 365)"),
    ownerId: z.number().optional().describe("Filter deals by owner/user ID (use get-users tool to find IDs)"),
    stageId: z.number().optional().describe("Filter deals by stage ID"),
    status: z.enum(['open', 'won', 'lost', 'deleted']).optional().describe("Filter deals by status (default: open)"),
    pipelineId: z.number().optional().describe("Filter deals by pipeline ID"),
    minValue: z.number().optional().describe("Minimum deal value filter"),
    maxValue: z.number().optional().describe("Maximum deal value filter"),
    limit: z.number().optional().describe("Maximum number of deals to return (default: 500)")
  },
  async ({
    searchTitle,
    daysBack = 365,
    ownerId,
    stageId,
    status = 'open',
    pipelineId,
    minValue,
    maxValue,
    limit = 500
  }) => {
    try {
      let filteredDeals: any[] = [];

      // If searching by title, use the search API first
      if (searchTitle) {
        // @ts-ignore - Bypass incorrect TypeScript definition
        const searchResponse = await dealsApi.searchDeals(searchTitle);
        filteredDeals = searchResponse.data || [];
      } else {
        // Calculate the date filter (daysBack days ago)
        const filterDate = new Date();
        filterDate.setDate(filterDate.getDate() - daysBack);
        const startDate = filterDate.toISOString().split('T')[0]; // Format as YYYY-MM-DD

        // Build API parameters (using actual Pipedrive API parameter names)
        const params: any = {
          sort: 'last_activity_date DESC',
          status: status,
          limit: limit
        };

        // Add optional filters
        if (ownerId) params.user_id = ownerId;
        if (stageId) params.stage_id = stageId;
        if (pipelineId) params.pipeline_id = pipelineId;

        // Fetch deals with filters
        // @ts-ignore - getDeals accepts parameters but types may be incomplete
        const response = await dealsApi.getDeals(params);
        filteredDeals = response.data || [];
      }

      // Apply additional client-side filtering

      // Filter by date if not searching by title
      if (!searchTitle) {
        const filterDate = new Date();
        filterDate.setDate(filterDate.getDate() - daysBack);

        filteredDeals = filteredDeals.filter((deal: any) => {
          if (!deal.last_activity_date) return false;
          const dealActivityDate = new Date(deal.last_activity_date);
          return dealActivityDate >= filterDate;
        });
      }

      // Filter by owner if specified and not already applied in API call
      if (ownerId && searchTitle) {
        filteredDeals = filteredDeals.filter((deal: any) => deal.owner_id === ownerId);
      }

      // Filter by status if specified and searching by title
      if (status && searchTitle) {
        filteredDeals = filteredDeals.filter((deal: any) => deal.status === status);
      }

      // Filter by stage if specified and not already applied in API call
      if (stageId && (searchTitle || !stageId)) {
        filteredDeals = filteredDeals.filter((deal: any) => deal.stage_id === stageId);
      }

      // Filter by pipeline if specified and not already applied in API call
      if (pipelineId && (searchTitle || !pipelineId)) {
        filteredDeals = filteredDeals.filter((deal: any) => deal.pipeline_id === pipelineId);
      }

      // Filter by value range if specified
      if (minValue !== undefined || maxValue !== undefined) {
        filteredDeals = filteredDeals.filter((deal: any) => {
          const value = parseFloat(deal.value) || 0;
          if (minValue !== undefined && value < minValue) return false;
          if (maxValue !== undefined && value > maxValue) return false;
          return true;
        });
      }

      // Apply limit
      if (filteredDeals.length > limit) {
        filteredDeals = filteredDeals.slice(0, limit);
      }

      // Build filter summary for response
      const filterSummary = {
        ...(searchTitle && { search_title: searchTitle }),
        ...(!searchTitle && { days_back: daysBack }),
        ...(!searchTitle && { filter_date: new Date(Date.now() - daysBack * 24 * 60 * 60 * 1000).toISOString().split('T')[0] }),
        status: status,
        ...(ownerId && { owner_id: ownerId }),
        ...(stageId && { stage_id: stageId }),
        ...(pipelineId && { pipeline_id: pipelineId }),
        ...(minValue !== undefined && { min_value: minValue }),
        ...(maxValue !== undefined && { max_value: maxValue }),
        total_deals_found: filteredDeals.length,
        limit_applied: limit
      };

      // Summarize deals to avoid massive responses
      const customFieldKey = process.env.PIPEDRIVE_CUSTOM_FIELD_KEY;
      const summarizedDeals = filteredDeals.map((deal: any) => {
        const summary: any = {
          id: deal.id,
          title: deal.title,
          value: deal.value,
          currency: deal.currency,
          status: deal.status,
          stage_name: deal.stage?.name || 'Unknown',
          pipeline_name: deal.pipeline?.name || 'Unknown',
          owner_name: deal.owner?.name || 'Unknown',
          organization_name: deal.org?.name || null,
          person_name: deal.person?.name || null,
          add_time: deal.add_time,
          last_activity_date: deal.last_activity_date,
          close_time: deal.close_time,
          won_time: deal.won_time,
          lost_time: deal.lost_time,
          notes_count: deal.notes_count || 0,
          notes: deal.notes || [],
        };
        if (customFieldKey && deal[customFieldKey]) {
          summary.custom_field = deal[customFieldKey];
        }
        return summary;
      });

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            summary: searchTitle
              ? `Found ${filteredDeals.length} deals matching title search "${searchTitle}"`
              : `Found ${filteredDeals.length} deals matching the specified filters`,
            filters_applied: filterSummary,
            total_found: filteredDeals.length,
            deals: summarizedDeals.slice(0, 30) // Limit to 30 deals max to prevent huge responses
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error fetching deals:", error);
      return {
        content: [{
          type: "text",
          text: `Error fetching deals: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get deal by ID
server.tool(
  "get-deal",
  "Get a specific deal by ID including custom fields",
  {
    dealId: z.number().describe("Pipedrive deal ID")
  },
  async ({ dealId }) => {
    try {
      // @ts-ignore - Bypass incorrect TypeScript definition, API expects just the ID
      const response = await dealsApi.getDeal(dealId);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error fetching deal ${dealId}:`, error);
      return {
        content: [{
          type: "text",
          text: `Error fetching deal ${dealId}: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get deal notes and custom booking details
server.tool(
  "get-deal-notes",
  "Get detailed notes and custom booking details for a specific deal",
  {
    dealId: z.number().describe("Pipedrive deal ID"),
    limit: z.number().optional().describe("Maximum number of notes to return (default: 20)")
  },
  async ({ dealId, limit = 20 }) => {
    try {
      const result: any = {
        deal_id: dealId,
        notes: [],
        booking_details: null
      };

      // Get deal details including custom fields
      try {
        // @ts-ignore - Bypass incorrect TypeScript definition
        const dealResponse = await dealsApi.getDeal(dealId);
        const deal = dealResponse.data;

        const customFieldKey = process.env.PIPEDRIVE_CUSTOM_FIELD_KEY;
        if (customFieldKey && deal && deal[customFieldKey]) {
          result.booking_details = deal[customFieldKey];
        }
      } catch (dealError) {
        console.error(`Error fetching deal details for ${dealId}:`, dealError);
        result.deal_error = getErrorMessage(dealError);
      }

      // Get deal notes
      try {
        // @ts-ignore - API parameters may not be fully typed
        // @ts-ignore - Bypass incorrect TypeScript definition
        const notesResponse = await notesApi.getNotes({
          deal_id: dealId,
          limit: limit
        });
        result.notes = notesResponse.data || [];
      } catch (noteError) {
        console.error(`Error fetching notes for deal ${dealId}:`, noteError);
        result.notes_error = getErrorMessage(noteError);
      }

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            summary: `Retrieved ${result.notes.length} notes and booking details for deal ${dealId}`,
            ...result
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error fetching deal notes ${dealId}:`, error);
      return {
        content: [{
          type: "text",
          text: `Error fetching deal notes ${dealId}: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Search deals
server.tool(
  "search-deals",
  "Search deals by term",
  {
    term: z.string().describe("Search term for deals")
  },
  async ({ term }) => {
    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await dealsApi.searchDeals(term);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error searching deals with term "${term}":`, error);
      return {
        content: [{
          type: "text",
          text: `Error searching deals: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get all persons
server.tool(
  "get-persons",
  "Get all persons from Pipedrive including custom fields",
  {},
  async () => {
    try {
      const response = await personsApi.getPersons();
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error fetching persons:", error);
      return {
        content: [{
          type: "text",
          text: `Error fetching persons: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get person by ID
server.tool(
  "get-person",
  "Get a specific person by ID including custom fields",
  {
    personId: z.number().describe("Pipedrive person ID")
  },
  async ({ personId }) => {
    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await personsApi.getPerson(personId);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error fetching person ${personId}:`, error);
      return {
        content: [{
          type: "text",
          text: `Error fetching person ${personId}: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Search persons
server.tool(
  "search-persons",
  "Search persons by term",
  {
    term: z.string().describe("Search term for persons")
  },
  async ({ term }) => {
    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await personsApi.searchPersons(term);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error searching persons with term "${term}":`, error);
      return {
        content: [{
          type: "text",
          text: `Error searching persons: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get all organizations
server.tool(
  "get-organizations",
  "Get all organizations from Pipedrive including custom fields",
  {},
  async () => {
    try {
      const response = await organizationsApi.getOrganizations();
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error fetching organizations:", error);
      return {
        content: [{
          type: "text",
          text: `Error fetching organizations: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get organization by ID
server.tool(
  "get-organization",
  "Get a specific organization by ID including custom fields",
  {
    organizationId: z.number().describe("Pipedrive organization ID")
  },
  async ({ organizationId }) => {
    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await organizationsApi.getOrganization(organizationId);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error fetching organization ${organizationId}:`, error);
      return {
        content: [{
          type: "text",
          text: `Error fetching organization ${organizationId}: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Search organizations
server.tool(
  "search-organizations",
  "Search organizations by term",
  {
    term: z.string().describe("Search term for organizations")
  },
  async ({ term }) => {
    try {
      // @ts-ignore - API method exists but TypeScript definition is wrong
      const response = await (organizationsApi as any).searchOrganization({ term });
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error searching organizations with term "${term}":`, error);
      return {
        content: [{
          type: "text",
          text: `Error searching organizations: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get all pipelines
server.tool(
  "get-pipelines",
  "Get all pipelines from Pipedrive",
  {},
  async () => {
    try {
      const response = await pipelinesApi.getPipelines();
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error fetching pipelines:", error);
      return {
        content: [{
          type: "text",
          text: `Error fetching pipelines: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get pipeline by ID
server.tool(
  "get-pipeline",
  "Get a specific pipeline by ID",
  {
    pipelineId: z.number().describe("Pipedrive pipeline ID")
  },
  async ({ pipelineId }) => {
    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await pipelinesApi.getPipeline(pipelineId);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error fetching pipeline ${pipelineId}:`, error);
      return {
        content: [{
          type: "text",
          text: `Error fetching pipeline ${pipelineId}: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get all stages
server.tool(
  "get-stages",
  "Get all stages from Pipedrive",
  {},
  async () => {
    try {
      // Since the stages are related to pipelines, we'll get all pipelines first
      const pipelinesResponse = await pipelinesApi.getPipelines();
      const pipelines = pipelinesResponse.data || [];
      
      // For each pipeline, fetch its stages
      const allStages = [];
      for (const pipeline of pipelines) {
        try {
          // @ts-ignore - Type definitions for getPipelineStages are incomplete
          const stagesResponse = await pipelinesApi.getPipelineStages(pipeline.id);
          const stagesData = Array.isArray(stagesResponse?.data)
            ? stagesResponse.data
            : [];

          if (stagesData.length > 0) {
            const pipelineStages = stagesData.map((stage: any) => ({
              ...stage,
              pipeline_name: pipeline.name
            }));
            allStages.push(...pipelineStages);
          }
        } catch (e) {
          console.error(`Error fetching stages for pipeline ${pipeline.id}:`, e);
        }
      }
      
      return {
        content: [{
          type: "text",
          text: JSON.stringify(allStages, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error fetching stages:", error);
      return {
        content: [{
          type: "text",
          text: `Error fetching stages: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Search leads
server.tool(
  "search-leads",
  "Search leads by term",
  {
    term: z.string().describe("Search term for leads")
  },
  async ({ term }) => {
    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await leadsApi.searchLeads(term);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error searching leads with term "${term}":`, error);
      return {
        content: [{
          type: "text",
          text: `Error searching leads: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Generic search across item types
server.tool(
  "search-all",
  "Search across all item types (deals, persons, organizations, etc.)",
  {
    term: z.string().describe("Search term"),
    itemTypes: z.string().optional().describe("Comma-separated list of item types to search (deal,person,organization,product,file,activity,lead)")
  },
  async ({ term, itemTypes }) => {
    try {
      const itemType = itemTypes; // Just rename the parameter
      const response = await itemSearchApi.searchItem({ 
        term,
        itemType 
      });
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error performing search with term "${term}":`, error);
      return {
        content: [{
          type: "text",
          text: `Error performing search: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// === DEALS (write) ===

const dealWriteFields = {
  title: z.string().optional().describe("Deal title"),
  value: z.number().optional().describe("Deal value (numeric)"),
  currency: z.string().optional().describe("ISO 4217 currency code, e.g. 'EUR', 'GBP', 'USD'"),
  personId: z.number().optional().describe("Linked person ID"),
  orgId: z.number().optional().describe("Linked organization ID"),
  pipelineId: z.number().optional().describe("Pipeline ID"),
  stageId: z.number().optional().describe("Stage ID (must belong to pipelineId if both given)"),
  ownerId: z.number().optional().describe("Owner user ID"),
  status: z.enum(['open', 'won', 'lost', 'deleted']).optional().describe("Deal status"),
  expectedCloseDate: z.string().optional().describe("Expected close date (YYYY-MM-DD)"),
  probability: z.number().optional().describe("Win probability 0-100"),
  lostReason: z.string().optional().describe("Free-text reason if status is 'lost'"),
  visibleTo: z.number().optional().describe("Visibility: 1=owner+followers, 3=entire company, 5=shared groups, 7=everyone"),
};

server.tool(
  "create-deal",
  "Create a new deal in Pipedrive. `title` is required.",
  {
    title: z.string().describe("Deal title (required)"),
    ...Object.fromEntries(Object.entries(dealWriteFields).filter(([k]) => k !== 'title')),
  },
  async (input) => {
    try {
      const { title, value, currency, personId, orgId, pipelineId, stageId, ownerId, status, expectedCloseDate, probability, lostReason, visibleTo } = input as any;
      const newDeal: Record<string, unknown> = { title };
      if (value !== undefined) newDeal.value = String(value);
      if (currency) newDeal.currency = currency;
      if (personId !== undefined) newDeal.person_id = personId;
      if (orgId !== undefined) newDeal.org_id = orgId;
      if (pipelineId !== undefined) newDeal.pipeline_id = pipelineId;
      if (stageId !== undefined) newDeal.stage_id = stageId;
      if (ownerId !== undefined) newDeal.user_id = ownerId;
      if (status) newDeal.status = status;
      if (expectedCloseDate) newDeal.expected_close_date = expectedCloseDate;
      if (probability !== undefined) newDeal.probability = probability;
      if (lostReason) newDeal.lost_reason = lostReason;
      if (visibleTo !== undefined) newDeal.visible_to = visibleTo;

      // @ts-ignore - DealsApi.addDeal not in local types
      const response = await dealsApi.addDeal({ newDeal });
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ summary: `Created deal ${response.data?.id}`, deal: response.data }, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error creating deal:", error);
      return { content: [{ type: "text", text: `Error creating deal: ${getErrorMessage(error)}` }], isError: true };
    }
  }
);

server.tool(
  "update-deal",
  "Update an existing deal. Only provide fields you want to change.",
  {
    dealId: z.number().describe("Pipedrive deal ID to update"),
    ...dealWriteFields,
  },
  async (input) => {
    try {
      const { dealId, title, value, currency, personId, orgId, pipelineId, stageId, ownerId, status, expectedCloseDate, probability, lostReason, visibleTo } = input as any;
      const updateDealRequest: Record<string, unknown> = {};
      if (title !== undefined) updateDealRequest.title = title;
      if (value !== undefined) updateDealRequest.value = String(value);
      if (currency !== undefined) updateDealRequest.currency = currency;
      if (personId !== undefined) updateDealRequest.person_id = personId;
      if (orgId !== undefined) updateDealRequest.org_id = orgId;
      if (pipelineId !== undefined) updateDealRequest.pipeline_id = pipelineId;
      if (stageId !== undefined) updateDealRequest.stage_id = stageId;
      if (ownerId !== undefined) updateDealRequest.user_id = ownerId;
      if (status !== undefined) updateDealRequest.status = status;
      if (expectedCloseDate !== undefined) updateDealRequest.expected_close_date = expectedCloseDate;
      if (probability !== undefined) updateDealRequest.probability = probability;
      if (lostReason !== undefined) updateDealRequest.lost_reason = lostReason;
      if (visibleTo !== undefined) updateDealRequest.visible_to = visibleTo;

      if (Object.keys(updateDealRequest).length === 0) {
        return { content: [{ type: "text", text: "Error: provide at least one field to update." }], isError: true };
      }

      // @ts-ignore - DealsApi.updateDeal not in local types
      const response = await dealsApi.updateDeal(dealId, { updateDealRequest });
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ summary: `Updated deal ${dealId}`, deal: response.data }, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error updating deal ${(input as any).dealId}:`, error);
      return { content: [{ type: "text", text: `Error updating deal: ${getErrorMessage(error)}` }], isError: true };
    }
  }
);

server.tool(
  "delete-deal",
  "Delete a deal by ID. Pipedrive keeps it recoverable in trash for ~30 days.",
  { dealId: z.number().describe("Pipedrive deal ID to delete") },
  async ({ dealId }) => {
    try {
      // @ts-ignore - DealsApi.deleteDeal not in local types
      const response = await dealsApi.deleteDeal(dealId);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ summary: `Deleted deal ${dealId}`, result: response.data ?? { success: true } }, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error deleting deal ${dealId}:`, error);
      return { content: [{ type: "text", text: `Error deleting deal ${dealId}: ${getErrorMessage(error)}` }], isError: true };
    }
  }
);

// === PERSONS (write) ===

const toContactArray = (vals: string[] | undefined) =>
  vals?.map((value, i) => ({ value, primary: i === 0 }));

const personWriteFields = {
  name: z.string().optional().describe("Person's full name"),
  ownerId: z.number().optional().describe("Owner user ID"),
  orgId: z.number().optional().describe("Linked organization ID"),
  emails: z.array(z.string()).optional().describe("Email addresses (first is marked primary)"),
  phones: z.array(z.string()).optional().describe("Phone numbers (first is marked primary)"),
  label: z.number().optional().describe("Label ID"),
  visibleTo: z.number().optional().describe("Visibility: 1=owner+followers, 3=entire company, 5=shared groups, 7=everyone"),
};

server.tool(
  "create-person",
  "Create a new person in Pipedrive. `name` is required.",
  {
    name: z.string().describe("Person's full name (required)"),
    ...Object.fromEntries(Object.entries(personWriteFields).filter(([k]) => k !== 'name')),
  },
  async (input) => {
    try {
      const { name, ownerId, orgId, emails, phones, label, visibleTo } = input as any;
      const newPerson: Record<string, unknown> = { name };
      if (ownerId !== undefined) newPerson.owner_id = ownerId;
      if (orgId !== undefined) newPerson.org_id = orgId;
      const emailArr = toContactArray(emails);
      if (emailArr) newPerson.email = emailArr;
      const phoneArr = toContactArray(phones);
      if (phoneArr) newPerson.phone = phoneArr;
      if (label !== undefined) newPerson.label = label;
      if (visibleTo !== undefined) newPerson.visible_to = visibleTo;

      // @ts-ignore - PersonsApi.addPerson not in local types
      const response = await personsApi.addPerson({ newPerson });
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ summary: `Created person ${response.data?.id}`, person: response.data }, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error creating person:", error);
      return { content: [{ type: "text", text: `Error creating person: ${getErrorMessage(error)}` }], isError: true };
    }
  }
);

server.tool(
  "update-person",
  "Update an existing person. Only provide fields you want to change.",
  {
    personId: z.number().describe("Pipedrive person ID to update"),
    ...personWriteFields,
  },
  async (input) => {
    try {
      const { personId, name, ownerId, orgId, emails, phones, label, visibleTo } = input as any;
      const updatePerson: Record<string, unknown> = {};
      if (name !== undefined) updatePerson.name = name;
      if (ownerId !== undefined) updatePerson.owner_id = ownerId;
      if (orgId !== undefined) updatePerson.org_id = orgId;
      const emailArr = toContactArray(emails);
      if (emailArr) updatePerson.email = emailArr;
      const phoneArr = toContactArray(phones);
      if (phoneArr) updatePerson.phone = phoneArr;
      if (label !== undefined) updatePerson.label = label;
      if (visibleTo !== undefined) updatePerson.visible_to = visibleTo;

      if (Object.keys(updatePerson).length === 0) {
        return { content: [{ type: "text", text: "Error: provide at least one field to update." }], isError: true };
      }

      // @ts-ignore - PersonsApi.updatePerson not in local types
      const response = await personsApi.updatePerson(personId, { updatePerson });
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ summary: `Updated person ${personId}`, person: response.data }, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error updating person ${(input as any).personId}:`, error);
      return { content: [{ type: "text", text: `Error updating person: ${getErrorMessage(error)}` }], isError: true };
    }
  }
);

server.tool(
  "delete-person",
  "Delete a person by ID. Pipedrive keeps them recoverable in trash for ~30 days.",
  { personId: z.number().describe("Pipedrive person ID to delete") },
  async ({ personId }) => {
    try {
      // @ts-ignore - PersonsApi.deletePerson not in local types
      const response = await personsApi.deletePerson(personId);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ summary: `Deleted person ${personId}`, result: response.data ?? { success: true } }, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error deleting person ${personId}:`, error);
      return { content: [{ type: "text", text: `Error deleting person ${personId}: ${getErrorMessage(error)}` }], isError: true };
    }
  }
);

// === ORGANIZATIONS (write) ===

const organizationWriteFields = {
  name: z.string().optional().describe("Organization name"),
  ownerId: z.number().optional().describe("Owner user ID"),
  label: z.number().optional().describe("Label ID"),
  visibleTo: z.number().optional().describe("Visibility: 1=owner+followers, 3=entire company, 5=shared groups, 7=everyone"),
};

server.tool(
  "create-organization",
  "Create a new organization in Pipedrive. `name` is required.",
  {
    name: z.string().describe("Organization name (required)"),
    ...Object.fromEntries(Object.entries(organizationWriteFields).filter(([k]) => k !== 'name')),
  },
  async (input) => {
    try {
      const { name, ownerId, label, visibleTo } = input as any;
      const newOrganization: Record<string, unknown> = { name };
      if (ownerId !== undefined) newOrganization.owner_id = ownerId;
      if (label !== undefined) newOrganization.label = label;
      if (visibleTo !== undefined) newOrganization.visible_to = visibleTo;

      // @ts-ignore - OrganizationsApi.addOrganization not in local types
      const response = await organizationsApi.addOrganization({ newOrganization });
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ summary: `Created organization ${response.data?.id}`, organization: response.data }, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error creating organization:", error);
      return { content: [{ type: "text", text: `Error creating organization: ${getErrorMessage(error)}` }], isError: true };
    }
  }
);

server.tool(
  "update-organization",
  "Update an existing organization. Only provide fields you want to change.",
  {
    organizationId: z.number().describe("Pipedrive organization ID to update"),
    ...organizationWriteFields,
  },
  async (input) => {
    try {
      const { organizationId, name, ownerId, label, visibleTo } = input as any;
      const updateOrganization: Record<string, unknown> = {};
      if (name !== undefined) updateOrganization.name = name;
      if (ownerId !== undefined) updateOrganization.owner_id = ownerId;
      if (label !== undefined) updateOrganization.label = label;
      if (visibleTo !== undefined) updateOrganization.visible_to = visibleTo;

      if (Object.keys(updateOrganization).length === 0) {
        return { content: [{ type: "text", text: "Error: provide at least one field to update." }], isError: true };
      }

      // @ts-ignore - OrganizationsApi.updateOrganization not in local types
      const response = await organizationsApi.updateOrganization(organizationId, { updateOrganization });
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ summary: `Updated organization ${organizationId}`, organization: response.data }, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error updating organization ${(input as any).organizationId}:`, error);
      return { content: [{ type: "text", text: `Error updating organization: ${getErrorMessage(error)}` }], isError: true };
    }
  }
);

server.tool(
  "delete-organization",
  "Delete an organization by ID. Pipedrive keeps it recoverable in trash for ~30 days.",
  { organizationId: z.number().describe("Pipedrive organization ID to delete") },
  async ({ organizationId }) => {
    try {
      // @ts-ignore - OrganizationsApi.deleteOrganization not in local types
      const response = await organizationsApi.deleteOrganization(organizationId);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ summary: `Deleted organization ${organizationId}`, result: response.data ?? { success: true } }, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error deleting organization ${organizationId}:`, error);
      return { content: [{ type: "text", text: `Error deleting organization ${organizationId}: ${getErrorMessage(error)}` }], isError: true };
    }
  }
);

// === LEADS (CRUD) ===

const leadWriteFields = {
  title: z.string().optional().describe("Lead title"),
  ownerId: z.number().optional().describe("Owner user ID"),
  personId: z.number().optional().describe("Linked person ID"),
  organizationId: z.number().optional().describe("Linked organization ID"),
  valueAmount: z.number().optional().describe("Lead value amount"),
  valueCurrency: z.string().optional().describe("Lead value currency (ISO 4217, e.g. 'EUR')"),
  expectedCloseDate: z.string().optional().describe("Expected close date (YYYY-MM-DD)"),
  labelIds: z.array(z.string()).optional().describe("Label UUIDs"),
  visibleTo: z.number().optional().describe("Visibility: 1=owner+followers, 3=entire company, 5=shared groups, 7=everyone"),
};

const buildLeadValue = (amount?: number, currency?: string) => {
  if (amount === undefined && !currency) return undefined;
  return { amount: amount ?? 0, currency: currency ?? 'EUR' };
};

server.tool(
  "create-lead",
  "Create a new lead in Pipedrive. `title` is required. A lead must be linked to a person or organization.",
  {
    title: z.string().describe("Lead title (required)"),
    ...Object.fromEntries(Object.entries(leadWriteFields).filter(([k]) => k !== 'title')),
  },
  async (input) => {
    try {
      const { title, ownerId, personId, organizationId, valueAmount, valueCurrency, expectedCloseDate, labelIds, visibleTo } = input as any;
      if (personId === undefined && organizationId === undefined) {
        return { content: [{ type: "text", text: "Error: a lead must be linked to a person (personId) or organization (organizationId)." }], isError: true };
      }

      const addLeadRequest: Record<string, unknown> = { title };
      if (ownerId !== undefined) addLeadRequest.owner_id = ownerId;
      if (personId !== undefined) addLeadRequest.person_id = personId;
      if (organizationId !== undefined) addLeadRequest.organization_id = organizationId;
      const value = buildLeadValue(valueAmount, valueCurrency);
      if (value) addLeadRequest.value = value;
      if (expectedCloseDate) addLeadRequest.expected_close_date = expectedCloseDate;
      if (labelIds) addLeadRequest.label_ids = labelIds;
      if (visibleTo !== undefined) addLeadRequest.visible_to = visibleTo;

      // @ts-ignore - LeadsApi.addLead not in local types
      const response = await leadsApi.addLead({ addLeadRequest });
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ summary: `Created lead ${response.data?.id}`, lead: response.data }, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error creating lead:", error);
      return { content: [{ type: "text", text: `Error creating lead: ${getErrorMessage(error)}` }], isError: true };
    }
  }
);

server.tool(
  "get-lead",
  "Get a single lead by its ID (UUID string).",
  {
    leadId: z.string().describe("Pipedrive lead ID (UUID)")
  },
  async ({ leadId }) => {
    try {
      // @ts-ignore - LeadsApi.getLead not in local types
      const response = await leadsApi.getLead(leadId);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error fetching lead ${leadId}:`, error);
      return { content: [{ type: "text", text: `Error fetching lead ${leadId}: ${getErrorMessage(error)}` }], isError: true };
    }
  }
);

server.tool(
  "list-leads",
  "List leads from Pipedrive, optionally filtered by owner, person, organization, or archived status.",
  {
    ownerId: z.number().optional().describe("Filter by owner user ID"),
    personId: z.number().optional().describe("Filter by linked person ID"),
    organizationId: z.number().optional().describe("Filter by linked organization ID"),
    archivedStatus: z.enum(['archived', 'not_archived', 'all']).optional().describe("Archived filter (default 'all')"),
    filterId: z.number().optional().describe("Apply a saved filter by ID"),
    sort: z.string().optional().describe("Sort, e.g. 'update_time DESC'"),
    limit: z.number().optional().describe("Max leads to return (default 100)"),
    start: z.number().optional().describe("Pagination start offset (default 0)"),
  },
  async ({ ownerId, personId, organizationId, archivedStatus, filterId, sort, limit = 100, start = 0 }) => {
    try {
      const opts: Record<string, unknown> = { limit, start };
      if (ownerId !== undefined) opts.ownerId = ownerId;
      if (personId !== undefined) opts.personId = personId;
      if (organizationId !== undefined) opts.organizationId = organizationId;
      if (archivedStatus) opts.archivedStatus = archivedStatus;
      if (filterId !== undefined) opts.filterId = filterId;
      if (sort) opts.sort = sort;

      // @ts-ignore - LeadsApi.getLeads not in local types
      const response = await leadsApi.getLeads(opts);
      const leads = response.data || [];

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            summary: `Found ${leads.length} leads`,
            filters_applied: opts,
            leads
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error listing leads:", error);
      return { content: [{ type: "text", text: `Error listing leads: ${getErrorMessage(error)}` }], isError: true };
    }
  }
);

server.tool(
  "update-lead",
  "Update an existing lead. Only provide fields you want to change. Use `isArchived` to archive/unarchive.",
  {
    leadId: z.string().describe("Pipedrive lead ID (UUID)"),
    ...leadWriteFields,
    isArchived: z.boolean().optional().describe("Archive (true) or unarchive (false) the lead"),
  },
  async (input) => {
    try {
      const { leadId, title, ownerId, personId, organizationId, valueAmount, valueCurrency, expectedCloseDate, labelIds, visibleTo, isArchived } = input as any;
      const updateLeadRequest: Record<string, unknown> = {};
      if (title !== undefined) updateLeadRequest.title = title;
      if (ownerId !== undefined) updateLeadRequest.owner_id = ownerId;
      if (personId !== undefined) updateLeadRequest.person_id = personId;
      if (organizationId !== undefined) updateLeadRequest.organization_id = organizationId;
      const value = buildLeadValue(valueAmount, valueCurrency);
      if (value) updateLeadRequest.value = value;
      if (expectedCloseDate !== undefined) updateLeadRequest.expected_close_date = expectedCloseDate;
      if (labelIds !== undefined) updateLeadRequest.label_ids = labelIds;
      if (visibleTo !== undefined) updateLeadRequest.visible_to = visibleTo;
      if (isArchived !== undefined) updateLeadRequest.is_archived = isArchived;

      if (Object.keys(updateLeadRequest).length === 0) {
        return { content: [{ type: "text", text: "Error: provide at least one field to update." }], isError: true };
      }

      // @ts-ignore - LeadsApi.updateLead not in local types
      const response = await leadsApi.updateLead(leadId, { updateLeadRequest });
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ summary: `Updated lead ${leadId}`, lead: response.data }, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error updating lead ${(input as any).leadId}:`, error);
      return { content: [{ type: "text", text: `Error updating lead: ${getErrorMessage(error)}` }], isError: true };
    }
  }
);

server.tool(
  "delete-lead",
  "Delete a lead by ID.",
  { leadId: z.string().describe("Pipedrive lead ID (UUID) to delete") },
  async ({ leadId }) => {
    try {
      // @ts-ignore - LeadsApi.deleteLead not in local types
      const response = await leadsApi.deleteLead(leadId);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ summary: `Deleted lead ${leadId}`, result: response.data ?? { success: true } }, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error deleting lead ${leadId}:`, error);
      return { content: [{ type: "text", text: `Error deleting lead ${leadId}: ${getErrorMessage(error)}` }], isError: true };
    }
  }
);

// === NOTES (CRUD) ===

const noteEntitySchema = {
  dealId: z.number().optional().describe("Attach the note to this deal ID"),
  personId: z.number().optional().describe("Attach the note to this person ID"),
  orgId: z.number().optional().describe("Attach the note to this organization ID"),
  leadId: z.string().optional().describe("Attach the note to this lead ID (UUID string)"),
};

// Create a note
server.tool(
  "create-note",
  "Create a note in Pipedrive. The note must be attached to at least one entity (deal, person, organization, or lead). Returns the created note with its ID.",
  {
    content: z.string().describe("Note content (supports HTML)"),
    ...noteEntitySchema,
    userId: z.number().optional().describe("User who owns the note (defaults to API token owner)"),
  },
  async ({ content, dealId, personId, orgId, leadId, userId }) => {
    try {
      if (!dealId && !personId && !orgId && !leadId) {
        return {
          content: [{
            type: "text",
            text: "Error: a note must be attached to at least one of dealId, personId, orgId, or leadId."
          }],
          isError: true
        };
      }

      const addNoteRequest: Record<string, unknown> = { content };
      if (dealId !== undefined) addNoteRequest.deal_id = dealId;
      if (personId !== undefined) addNoteRequest.person_id = personId;
      if (orgId !== undefined) addNoteRequest.org_id = orgId;
      if (leadId !== undefined) addNoteRequest.lead_id = leadId;
      if (userId !== undefined) addNoteRequest.user_id = userId;

      // @ts-ignore - NotesApi types not declared locally
      const response = await notesApi.addNote({ addNoteRequest });

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            summary: `Created note ${response.data?.id}`,
            note: response.data
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error creating note:", error);
      return {
        content: [{
          type: "text",
          text: `Error creating note: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get a single note by ID
server.tool(
  "get-note",
  "Get a single note by its ID",
  {
    noteId: z.number().describe("Pipedrive note ID")
  },
  async ({ noteId }) => {
    try {
      // @ts-ignore - NotesApi types not declared locally
      const response = await notesApi.getNote(noteId);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error fetching note ${noteId}:`, error);
      return {
        content: [{
          type: "text",
          text: `Error fetching note ${noteId}: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// List notes with filters
server.tool(
  "list-notes",
  "List notes from Pipedrive, optionally filtered by deal, person, organization, lead, user, or date range.",
  {
    ...noteEntitySchema,
    userId: z.number().optional().describe("Filter notes by author user ID"),
    startDate: z.string().optional().describe("Earliest note date (YYYY-MM-DD)"),
    endDate: z.string().optional().describe("Latest note date (YYYY-MM-DD)"),
    sort: z.string().optional().describe("Sort, e.g. 'update_time DESC' (supported fields: id, user_id, deal_id, person_id, org_id, content, add_time, update_time)"),
    limit: z.number().optional().describe("Max notes to return (default 50, max 500)"),
    start: z.number().optional().describe("Pagination start offset (default 0)"),
  },
  async ({ dealId, personId, orgId, leadId, userId, startDate, endDate, sort, limit = 50, start = 0 }) => {
    try {
      const opts: Record<string, unknown> = { limit, start };
      if (dealId !== undefined) opts.dealId = dealId;
      if (personId !== undefined) opts.personId = personId;
      if (orgId !== undefined) opts.orgId = orgId;
      if (leadId !== undefined) opts.leadId = leadId;
      if (userId !== undefined) opts.userId = userId;
      if (startDate) opts.startDate = startDate;
      if (endDate) opts.endDate = endDate;
      if (sort) opts.sort = sort;

      // @ts-ignore - NotesApi types not declared locally
      const response = await notesApi.getNotes(opts);
      const notes = response.data || [];

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            summary: `Found ${notes.length} notes`,
            filters_applied: opts,
            notes
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error listing notes:", error);
      return {
        content: [{
          type: "text",
          text: `Error listing notes: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Update a note
server.tool(
  "update-note",
  "Update an existing note. Only provide fields you want to change. At minimum, content is usually what you'd change.",
  {
    noteId: z.number().describe("Pipedrive note ID to update"),
    content: z.string().optional().describe("New note content"),
    ...noteEntitySchema,
    userId: z.number().optional().describe("Reassign the note to this user"),
  },
  async ({ noteId, content, dealId, personId, orgId, leadId, userId }) => {
    try {
      const note: Record<string, unknown> = {};
      if (content !== undefined) note.content = content;
      if (dealId !== undefined) note.deal_id = dealId;
      if (personId !== undefined) note.person_id = personId;
      if (orgId !== undefined) note.org_id = orgId;
      if (leadId !== undefined) note.lead_id = leadId;
      if (userId !== undefined) note.user_id = userId;

      if (Object.keys(note).length === 0) {
        return {
          content: [{
            type: "text",
            text: "Error: nothing to update — provide at least one field (content, dealId, personId, orgId, leadId, or userId)."
          }],
          isError: true
        };
      }

      // @ts-ignore - NotesApi types not declared locally
      const response = await notesApi.updateNote(noteId, { note });

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            summary: `Updated note ${noteId}`,
            note: response.data
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error updating note ${noteId}:`, error);
      return {
        content: [{
          type: "text",
          text: `Error updating note ${noteId}: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Delete a note
server.tool(
  "delete-note",
  "Delete a note by its ID. This is destructive and cannot be undone via the API.",
  {
    noteId: z.number().describe("Pipedrive note ID to delete")
  },
  async ({ noteId }) => {
    try {
      // @ts-ignore - NotesApi types not declared locally
      const response = await notesApi.deleteNote(noteId);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            summary: `Deleted note ${noteId}`,
            result: response.data ?? { success: true }
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error deleting note ${noteId}:`, error);
      return {
        content: [{
          type: "text",
          text: `Error deleting note ${noteId}: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// === PROMPTS ===

// Prompt for getting all deals
server.prompt(
  "list-all-deals",
  "List all deals in Pipedrive",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please list all deals in my Pipedrive account, showing their title, value, status, and stage."
      }
    }]
  })
);

// Prompt for getting all persons
server.prompt(
  "list-all-persons",
  "List all persons in Pipedrive",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please list all persons in my Pipedrive account, showing their name, email, phone, and organization."
      }
    }]
  })
);

// Prompt for getting all pipelines
server.prompt(
  "list-all-pipelines",
  "List all pipelines in Pipedrive",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please list all pipelines in my Pipedrive account, showing their name and stages."
      }
    }]
  })
);

// Prompt for analyzing deals
server.prompt(
  "analyze-deals",
  "Analyze deals by stage",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please analyze the deals in my Pipedrive account, grouping them by stage and providing total value for each stage."
      }
    }]
  })
);

// Prompt for analyzing contacts
server.prompt(
  "analyze-contacts",
  "Analyze contacts by organization",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please analyze the persons in my Pipedrive account, grouping them by organization and providing a count for each organization."
      }
    }]
  })
);

// Prompt for analyzing leads
server.prompt(
  "analyze-leads",
  "Analyze leads by status",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please search for all leads in my Pipedrive account and group them by status."
      }
    }]
  })
);

// Prompt for pipeline comparison
server.prompt(
  "compare-pipelines",
  "Compare different pipelines and their stages",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please list all pipelines in my Pipedrive account and compare them by showing the stages in each pipeline."
      }
    }]
  })
);

// Prompt for finding high-value deals
server.prompt(
  "find-high-value-deals",
  "Find high-value deals",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please identify the highest value deals in my Pipedrive account and provide information about which stage they're in and which person or organization they're associated with."
      }
    }]
  })
);

// Get transport type from environment variable (default to stdio)
const transportType = process.env.MCP_TRANSPORT || 'stdio';

if (transportType === 'sse') {
  // SSE transport - create HTTP server
  const port = parseInt(process.env.MCP_PORT || '3000', 10);
  const endpoint = process.env.MCP_ENDPOINT || '/message';

  // Store active transports by session ID
  const transports = new Map<string, SSEServerTransport>();

  const httpServer = http.createServer(async (req, res) => {
    const url = new URL(req.url!, `http://${req.headers.host}`);

    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Session-Id');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.method === 'GET' && url.pathname === '/sse') {
      const authResult = verifyRequestAuthentication(req);
      if (!authResult.ok) {
        res.writeHead(authResult.status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: authResult.message }));
        return;
      }

      // Establish SSE connection
      console.error('New SSE connection request');
      const transport = new SSEServerTransport(endpoint, res);

      // Store transport by session ID
      transports.set(transport.sessionId, transport);

      transport.onclose = () => {
        console.error(`SSE connection closed: ${transport.sessionId}`);
        transports.delete(transport.sessionId);
      };

      try {
        await server.connect(transport);
        console.error(`SSE connection established: ${transport.sessionId}`);
      } catch (err) {
        console.error('Failed to establish SSE connection:', err);
        transports.delete(transport.sessionId);
      }
    } else if (req.method === 'POST' && url.pathname === endpoint) {
      const authResult = verifyRequestAuthentication(req);
      if (!authResult.ok) {
        res.writeHead(authResult.status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: authResult.message }));
        return;
      }

      // Handle incoming message
      const sessionId = url.searchParams.get('sessionId') || req.headers['x-session-id'] as string;

      if (!sessionId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Missing sessionId' }));
        return;
      }

      const transport = transports.get(sessionId);
      if (!transport) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Session not found' }));
        return;
      }

      req.on('error', err => {
        console.error('Error receiving POST message body:', err);
        if (!res.headersSent) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid request body' }));
        }
      });

      try {
        await transport.handlePostMessage(req, res);
      } catch (err) {
        console.error('Error handling POST message:', err);
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Internal server error' }));
        }
      }
    } else {
      // Health check endpoint
      if (req.method === 'GET' && url.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', transport: 'sse' }));
        return;
      }

      res.writeHead(404);
      res.end('Not found');
    }
  });

  httpServer.listen(port, () => {
    console.error(`Pipedrive MCP Server (SSE) listening on port ${port}`);
    console.error(`SSE endpoint: http://localhost:${port}/sse`);
    console.error(`Message endpoint: http://localhost:${port}${endpoint}`);
  });
} else {
  // Default: stdio transport
  const transport = new StdioServerTransport();
  server.connect(transport).catch(err => {
    console.error("Failed to start MCP server:", err);
    process.exit(1);
  });

  console.error("Pipedrive MCP Server started (stdio transport)");
}
